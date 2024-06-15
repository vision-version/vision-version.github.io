@main def exec(cpgFile: String,Status: String)={
  importCpg(cpgFile)
  cpg.method.toJson|>s"${Status}_method.json"
}
