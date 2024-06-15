@main def exec(cpgFile: String,methodName: String,lineNumber:Int){
	importCpg(cpgFile)
	cpg.method(methodName).filter(node=>node.lineNumber==Some(lineNumber)).dotPdg.toJson|>"PDG.json"
	cpg.method(methodName).filter(node=>node.lineNumber==Some(lineNumber)).ast.isCall.filter(node=>node.methodFullName=="<operator>.assignment").map(node=>node.lineNumber).toJson|>"assignment.json"
	cpg.method(methodName).filter(node=>node.lineNumber==Some(lineNumber)).ast.isControlStructure.filter(node=>node.controlStructureType=="IF").map(node=>(node.lineNumber)).toJson|>"control.json"
	cpg.method(methodName).filter(node=>node.lineNumber==Some(lineNumber)).ast.isReturn.map(node=>node.lineNumber).toJson|>"return.json"
}
