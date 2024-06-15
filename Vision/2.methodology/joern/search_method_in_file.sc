@main def exec(cpgFile: String, fileName: String) = {
  importCpg(cpgFile)
  cpg.file.filter(n => n.name.contains(fileName)).method.map(n => n.fullName).l  |> "search_method_in_file.json"
}