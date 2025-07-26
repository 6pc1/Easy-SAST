/**
 * @id java/vul/xxe
 * @name xxe
 * @description xxe-vul
 * @kind path-problem
 * @problem.severity warning
 */

 import java
 import semmle.code.java.dataflow.FlowSources
 import semmle.code.java.dataflow.ExternalFlow
 import semmle.code.java.dataflow.DataFlow
 import XXEVul::PathGraph


 module XXEVulConfig implements DataFlow::ConfigSig {
    predicate isSource(DataFlow::Node source){
        source instanceof RemoteFlowSource
    }

    predicate isSink(DataFlow::Node sink){
        exists(Method method, MethodCall call |
            method.hasName("parse") and
            call.getMethod() = method and
            sink.asExpr() = call.getArgument(0)
        )
    }
 }


 module XXEVul = TaintTracking::Global<XXEVulConfig>;

 from XXEVul::PathNode source, XXEVul::PathNode sink
 where XXEVul::flowPath(source, sink)
 select source.getNode(), source, sink, "source"