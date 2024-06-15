@main def exec(cpgFile: String,methodFullName: String){
	importCpg(cpgFile)
	cpg.method.filter(node => node.fullName.contains(methodFullName_comma)).dotPdg.toJson|>"PDG.json"
	cpg.method.filter(node => node.fullName.contains(methodFullName_comma)).ast.isCall.filter(node=>node.methodFullName=="<operator>.assignment").map(node=>node.lineNumber).toJson|>"assignment.json"
	cpg.method.filter(node => node.fullName.contains(methodFullName_comma)).ast.isControlStructure.filter(node=>node.controlStructureType=="IF").map(node=>(node.lineNumber)).toJson|>"control.json"
	cpg.method.filter(node => node.fullName.contains(methodFullName_comma)).ast.isReturn.map(node=>node.lineNumber).toJson|>"return.json"
}
