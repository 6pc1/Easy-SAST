/**
 * @id java/vul/ssrf
 * @name ssrf-vul
 * @description ssrf-vul
 * @kind path-problem
 * @problem.severity warning
 */

 import java
 import semmle.code.java.dataflow.DataFlow
 import semmle.code.java.dataflow.FlowSources
 import semmle.code.java.dataflow.TaintTracking
 import semmle.code.java.security.QueryInjection
 import semmle.code.java.security.RequestForgeryConfig
 import SSRFVul::PathGraph


 MethodCall url(MethodCall ma, DataFlow::Node node){
    exists(MethodCall mc | mc = ma.getAChildExpr() | if mc.getCallee().hasName("url") and mc.getArgument(0) = node.asExpr()
    then result = mc else result = url(mc, node))
 }

 MethodCall m(DataFlow::Node node){
    exists(MethodCall ma | ma.getCallee().hasName("build")  and ma.getCallee().getDeclaringType().hasName("Builder") |
    result = url(ma, node)
    )
 }



 class TypeStringLib extends RefType {
    TypeStringLib() { this.hasQualifiedName("java.lang", "String")}
 }

 class StringValue extends MethodCall {
    StringValue() {
        this.getCallee().getDeclaringType() instanceof TypeStringLib and
        this.getCallee().hasName("valueOf")
    }
 }

 private class MyRequestForgeryAdditionalTaintStep extends RequestForgeryAdditionalTaintStep {
    override predicate propagatesTaint(DataFlow::Node pred, DataFlow::Node succ){
        exists(UriCreation c | c.getHostArg()=pred.asExpr() | succ.asExpr() = c)
        or
        exists(UrlConstructorCall c| c.getHostArg() = pred.asExpr()  | succ.asExpr() = c )
        or
        exists(StringValue c | c.getArgument(0) = pred.asExpr() | succ.asExpr() = c)
    }
 }


 module SSRFVulConfig implements DataFlow::ConfigSig {
    predicate isSource (DataFlow::Node source){
        source instanceof RemoteFlowSource and
        not source.asExpr().(MethodCall).getCallee() instanceof UrlConnectionGetInputStreamMethod
    }
    predicate isSink (DataFlow::Node sink){
        sink instanceof RequestForgerySink or
        exists(m(sink))
    }

    predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ){
        any(RequestForgeryAdditionalTaintStep r).propagatesTaint(pred, succ)
    }
 }


module SSRFVul = TaintTracking::Global<SSRFVulConfig>;

from SSRFVul::PathNode source, SSRFVul::PathNode sink
where SSRFVul::flowPath(source, sink)
select source.getNode(), source, sink, "source"