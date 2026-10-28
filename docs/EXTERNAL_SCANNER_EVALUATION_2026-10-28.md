# External scanner probes — October 28, 2026

These are exploratory third-party fixtures, inspected by the scanner and never executed. They are not blinded benchmarks, statistically representative samples, or exploitability labels. Findings counted below cannot be interpreted as precision or recall. The source is PyCQA/bandit examples on GitHub; content blob hashes identify the exact inspected contents.

| File | Content blob | Observations before targeted fixes |
| --- | --- | --- |
| subprocess_shell.py | 38944d5faf88a54267d920f9458c45c734925384 | Nine findings initially. Scanner 52 local rerun: six behavior and thirteen Semgrep findings, including additional explicit/implicit shell and truthy literals. Unknown/custom shell expressions remain unsupported. |
| eval.py | 72a8174ef7a5a39d5649ab1e115e62eb273464d8 | Arithmetic eval receives notice; two other eval operations high; user-defined eval methods not flagged. |
| exec.py | 17ac83a2731212f5957f0bad0d8eceebe1aa5b3a | Dynamic exec reported high. |
| yaml_load.py | a6a2eb164027ba7fa7494b12de4aaeb7a920f751 | No-loader warning detected; explicit yaml.Loader missed. Safe loader controls unflagged. |
| pickle_deserialize.py | 3c56c80492a023e3e85a0663d8c443302c3de580 | pickle.load/loads reported; direct Unpickler(stream).load missed. |

Both behavior and Semgrep reported complete on these selected inputs. This describes engine execution, not full vulnerability coverage. Fixed shell commands and locally created pickle streams are not proof of exploitable input.

Targeted deserializer changes add explicit yaml.Loader/yaml.UnsafeLoader positional and keyword forms, and direct pickle.Unpickler(...).load(...). Local real-engine controls include SafeLoader, CSafeLoader, json.load, and an unrelated load method. Indirect aliases, saved Unpickler instances, custom subclasses, dynamic dispatch and general interprocedural flow are not proven by these cases.

Scanner 52 deployed customer pair: string shell="False" medium warning vs boolean shell=False fixed argv zero findings; both engines complete, one allowance each. Deserializer deployment/customer verification is pending at authoring. Scanner/security sign-off remains open for severity calibration, broader evaluation, deployed customer isolation and repository regression. Site stays owner-private and purchases paused.
