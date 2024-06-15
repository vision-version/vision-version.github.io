@main def exec(i: String)={
  cpg.method.toJson|>"methodInfo/method_" + i + ".json"
}
