import json
import unittest
import ai_compare
import ai_single_review as review


def response(observations,limitations=None):
    report={'summary':'Review the cited source.','observations':observations,'limitations':limitations if limitations is not None else ['Only supplied source was reviewed.']}
    return {'status':'completed','output':[{'type':'message','content':[{'type':'output_text','text':json.dumps(report)}]}]}


class SingleCodeReviewContractTests(unittest.TestCase):
    def test_unicode_and_long_single_line_preserve_exact_evidence(self):
        code='message = "' + ('雪😀' * 900) + '"\nprint(message)'
        _,options=review.prepare({'code':code,'intent':'Print the message.'})
        self.assertEqual(''.join(option['text'] for option in options),code)
        self.assertTrue(all(option['first_line']==1 for option in options[:-1]))
        result=review.validate_response(response([{'classification':'requires_context','explanation':'Check the input.','evidence_id':options[-1]['id']}]),options)
        self.assertEqual(result['observations'][0]['evidence'],options[-1]['text'])

    def test_provider_cannot_supply_its_own_evidence_or_unknown_fields(self):
        _,options=review.prepare({'code':'print("ready")','intent':'Print a status.'})
        observation={'classification':'supports_intent','explanation':'The source prints a value.','evidence_id':options[0]['id'],'evidence':'forged'}
        with self.assertRaises(ai_compare.InvalidResult):review.validate_response(response([observation]),options)

    def test_all_source_is_preserved_and_excerpts_are_bounded(self):
        code='x="'+('a'*4000)+'"\r\nprint(x)\n'
        payload,options=review.prepare({'code':code,'intent':'Print a value.'})
        self.assertEqual(''.join(o['text'] for o in options),code)
        self.assertTrue(all(len(o['text'])<=review.MAX_EXCERPT_CHARS for o in options))
        self.assertEqual(options[0]['first_line'],1)
        self.assertIn('untrusted data',payload['instructions'])
        self.assertFalse(payload['store'])

    def test_exact_server_attached_evidence_and_forgery_rejection(self):
        _,options=review.prepare({'code':'import os\nprint(os.getenv("PORT"))\n','intent':'Print a local port.'})
        observation={'classification':'requires_context','explanation':'The value depends on the environment.','evidence_id':options[0]['id']}
        result=review.validate_response(response([observation]),options)
        self.assertEqual(result['observations'][0]['evidence'],options[0]['text'])
        observation['evidence_id']='fabricated'
        with self.assertRaises(ai_compare.InvalidResult):review.validate_response(response([observation]),options)

    def test_empty_limit_and_invalid_provider_results_fail_closed(self):
        for body in [{'code':'','intent':'do work'},{'code':'x','intent':''},{'code':'x'*32001,'intent':'do work'}]:
            with self.assertRaises(ai_compare.InvalidInput):review.prepare(body)
        _,options=review.prepare({'code':'print(1)','intent':'Print one.'})
        for payload in [{'status':'incomplete'},response([],[]),{'status':'completed','output':['malformed']}]:
            with self.assertRaises(ai_compare.InvalidResult):review.validate_response(payload,options)
