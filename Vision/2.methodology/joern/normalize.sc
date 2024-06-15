@main def exec(cpgFile: String,methodName: String,line: Int){
    importCpg(cpgFile)
    cpg.method(methodName).filter(node=>(node.lineNumber==Some(value=line))).ast.isIdentifier.filter(node=>(cpg.method(methodName).filter(node=>(node.lineNumber==Some(value=line))).ast.isParameter.name.l.contains(node.name))).map(node=>(node.code,node.lineNumber,node.columnNumber)).toJson|>"FP.json"
    (cpg.method(methodName).filter(node=>(node.lineNumber==Some(value=line))).ast.isIdentifier.filterNot(node=>(cpg.method(methodName).filter(node=>(node.lineNumber==Some(value=line))).ast.isParameter.name.l.contains(node.name))).map(node=>(node.code,node.lineNumber,node.columnNumber)).toSet++cpg.method(methodName).filter(node=>(node.lineNumber==Some(value=line))).ast.isLocal.map(node=>(node.name,node.lineNumber,node.columnNumber)).toSet).l|>"LV.json"
    cpg.method(methodName).filter(node=>(node.lineNumber==Some(value=line))).ast.isLocal.map(node=>(node.code,node.name,node.typeFullName,node.lineNumber,node.columnNumber)).toJson|>"DT.json"
    cpg.method(methodName).filter(node=>(node.lineNumber==Some(value=line))).ast.isCall.filterNot(node=>(node.methodFullName.matches("<operator>.*")||(node.methodFullName.matches("<operators>.*")))).map(node=>(node.name,node.lineNumber,node.columnNumber)).toJson|>"FC.json"
    cpg.method(methodName).filter(node=>(node.lineNumber==Some(value=line))).ast.isLiteral.filter(node=>node.typeFullName=="char").map(node=>(node.code,node.lineNumber,node.columnNumber)).toJson|>"STRING.json"
}
