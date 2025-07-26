/**
 * @id java/vul/sql
 * @name Sql-Injection
 * @description Sql-Injection
 * @kind path-problem
 * @problem.severity warning
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.security.QueryInjection
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import VulFlow::PathGraph


predicate isTaintedString(Expr expSrc, Expr expDest){
    // 这里是强制将username传递到了username.get()
    exists(Method method, MethodCall call1, MethodCall call2 |
        expSrc = call2.getArgument(0) and expDest = call1 and
        call1.getMethod() = method and method.hasName("get") and
        method.getDeclaringType().toString() = "Optional<String>" and
        call2.getArgument(0).getType().toString() = "Optional<String>")
}

module VulConfig implements DataFlow::ConfigSig {
    predicate isSource(DataFlow::Node source) {
        source instanceof RemoteFlowSource
    }

    predicate isSink(DataFlow::Node sink) {
        exists(Method method, MethodCall call | method.hasName("query") and call.getMethod() = method and sink.asExpr() = call.getArgument(0))
    }

    predicate isBarrier(DataFlow::Node sanitizer){
        sanitizer.getType() instanceof PrimitiveType or
        sanitizer.getType() instanceof BoxedType or
        sanitizer.getType() instanceof NumberType or
        exists(ParameterizedType pt|sanitizer.getType() = pt and pt.getTypeArgument(0) instanceof NumberType
        )
    }

    predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2){
        isTaintedString(node1.asExpr(), node2.asExpr())
    }

}


module VulFlow = TaintTracking::Global<VulConfig>;

from VulFlow::PathNode source, VulFlow::PathNode sink
where VulFlow::flowPath(source, sink)
select source.getNode(), source, sink, "source"