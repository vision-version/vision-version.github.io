object TaintAnalysis {
  def main(args: Array[String]): Unit = {
    if (args.length < 3) {
      println("Usage: scala TaintAnalysis.scala <path_to_cpg> <method_name> <exit_point>")
      return
    }
    val cpg = CpgLoader.load(args(0))
    val methodName = args(1)
    val exitPoint = args(2)

    def source = cpg.method.filter(_.fullName.contains(methodName)).parameter
    def sink = cpg.method.filter(_.fullName.contains(exitPoint))
      .repeat(_.astChildren)(_.times(4))
      .isIdentifier
    val flows = sink.reachableBy(source).l
    flows.foreach(println)
  }
}