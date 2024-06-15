@main def exec(line: Int, i: String){
	cpg.method.filter(node=>(node.lineNumber==Some(value=line))).dotPdg.toJson|>"PDG/PDG_" + i + ".json"
	cpg.method.filter(node=>(node.lineNumber==Some(value=line))).ast.isCall.filter(node=>node.methodFullName=="<operator>.assignment").map(node=>node.lineNumber).toJson|>"assign/assignment_" + i + ".json"
	cpg.method.filter(node=>(node.lineNumber==Some(value=line))).ast.isControlStructure.filter(node=>node.controlStructureType=="IF").map(node=>(node.lineNumber)).toJson|>"control/control_" + i + ".json"
	cpg.method.filter(node=>(node.lineNumber==Some(value=line))).ast.isReturn.map(node=>node.lineNumber).toJson|>"ret/return_" + i + ".json"
}
