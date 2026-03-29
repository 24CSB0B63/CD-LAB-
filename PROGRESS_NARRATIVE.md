Progress Documentation

Week 1: Problem Definition
Spent this week studying how SQL injection works in different codebases. Defined the scope of the project to focus on C++ applications and established the basic objectives for catching vulnerabilities during compilation.

Week 2: Research and Literature
Reviewed existing research papers on static taint analysis and looked at tools like SonarQube and CodeQL. Identified some gaps in how these tools handle complex logic in C++ and decided to build an LLVM-based solution.

Week 3: Functional Requirements
Focus was on identifying exactly what needs to be tracked. Made a list of input sources like cin and getenv and mapped out the sensitive database sinks that need protection. Performed some threat analysis on common bypass techniques.

Week 4: System Architecture
Designed the overall architecture for the compiler pass. Decided on a module-level pass that can look at the whole application at once. Planned out how the taint labels would be stored and moved between variables.

Week 5: Grammar and Input Sources
Started implementing the actual code logic to identify untrusted boundaries. Dealt with C++ name mangling to correctly find standard library functions in the LLVM IR. Built the logic to recognize common input sources.

Week 6: Initial Taint Propagation
Built the first version of the propagation engine. Used a fixed-point iteration approach to ensure that if data is moved through multiple variables, the taint follows it. Started handling simple memory operations like loads and stores.

Week 7: Core Analysis and Inter-Procedural Logic
Expanded the analysis to work across different functions. Implemented bi-directional argument tracking so that data passed into or returned from functions still carries its taint status correctly. Added a feature to inject a warning function directly into the compiled binary.

Week 8: IR Pattern Detection
Focused on identifying vulnerable string building patterns. Implemented logic to scan for SQL keywords in concatenated strings. This helps distinguish between regular string usage and actual SQL query construction which is much more likely to be dangerous.

Week 9: Sanitization Heuristics
Integrated logic to recognize security functions that clean user input. If a variable passes through a recognized sanitizer like an escaping function, the pass now untaints it. This was important to reduce the number of false alarms in the system.

Week 10: Performance Optimization
Completed the tasks mentioned in the execution plan for this week. Focused on making the analysis more efficient when dealing with large modules.

Week 11: Testing and Verification
Completed the tasks mentioned in the execution plan. Ran the pass against several benchmarks to ensure that basic vulnerabilities are always caught without missing anything obvious.

Week 12: Benchmarking and Comparison
Completed the tasks mentioned in the execution plan. Measured the precision and recall of the detection logic and compared the results against baseline static analysis tools.

Week 13: GUI Integration and Explainability
Built a web-based dashboard using Python and Cytoscape.js. Users can now upload their code and see a visual map of the taint path from source to sink. Added a feature to map the low-level LLVM instructions back to the original source line numbers in the editor.
