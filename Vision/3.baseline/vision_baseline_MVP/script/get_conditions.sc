@main def exec(cpgFile: String,line: Int){
    importCpg(cpgFile)
    cpg.method.filter(node=>node.lineNumber==Some(value=line)).ast.inAstMinusLeaf.isCall.name(".*logicalNot.*").map(node=>(node.code,node.lineNumber)).toJson |> "conditions.json" 
    cpg.method.filter(node=>node.lineNumber==Some(value=line)).ast.inAstMinusLeaf.isCall.name(".*greaterEqualsThan.*").map(node=>(node.code,node.lineNumber)).toJson |> "GET.json"
    cpg.method.filter(node=>node.lineNumber==Some(value=line)).ast.inAstMinusLeaf.isCall.name(".*lessEqualsThan.*").map(node=>(node.code,node.lineNumber)).toJson |> "LET.json"
}
