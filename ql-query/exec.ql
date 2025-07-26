/**
 * @id java/vul/execql
 * @name command-exec
 * @description vul-of-exec
 * @kind path-problem
 * @problem.severity warning
 */


import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import ExecVul::PathGraph

module ExecVulConfig implements DataFlow::ConfigSig {
    predicate isSink(DataFlow::Node sink) {
        sink.asExpr() instanceof ArgumentToExec
    }

    predicate isSource(DataFlow::Node source) {
        source instanceof RemoteFlowSource
    }
}


module ExecVul = TaintTracking::Global<ExecVulConfig>;


from ExecVul::PathNode source, ExecVul::PathNode sink
where ExecVul::flowPath(source, sink)
select source.getNode(), source, sink, "source"