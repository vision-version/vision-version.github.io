@main def exec(cpgFile: String, methodFullName: String, methodCode: String) = {
  importCpg(cpgFile)
  cpg.method.filter(node => node.fullName.contains(methodFullName) && node.code.contains(replacedCode)).repeat(_.caller)(_.times(1)).toJson |> "methodcaller.json"
}