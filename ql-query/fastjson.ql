/**
 * @id java/vul/fastjson
 * @name fastjson-vul
 * @description fastjson-vul
 * @kind path-problem
 * @problem.severity warning
 */


 import java
 import semmle.code.java.dataflow.DataFlow
 import semmle.code.java.dataflow.FlowSources
 import semmle.code.java.dataflow.TaintTracking
 import FastjsonVul::PathGraph

 module FastjsonVulConfig implements DataFlow::ConfigSig{
    predicate isSource(DataFlow::Node source){
        source instanceof RemoteFlowSource
    }

    predicate isSink(DataFlow::Node sink){
        exists(Method method, MethodCall call |
            method.hasName("parseObject")
            and call.getMethod() = method and
            sink.asExpr() = call.getArgument(0)
            )
    }
 }

 module FastjsonVul = TaintTracking::Global<FastjsonVulConfig>;

 from FastjsonVul::PathNode source, FastjsonVul::PathNode sink
 where FastjsonVul::flowPath(source, sink)
 select source.getNode(), source, sink, "source"