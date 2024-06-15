def getCallSite(callerMethodFullName: String, calleeMethodFullName: String) = {

    val line_no = cpg.call.filter(n => n.methodFullName.contains(calleeMethod)).location.filter(n => n.methodFullName.contains(callerMethod)).map(n => List(n.filename, n.lineNumber)).l

    print(line_no)
}

@main def callsite(cpgFile: String, callerMethodFullName: String, calleeMethodFullName: String) = {
    importCpg(cpgFile)
    getCallSite(callerMethodFullName, calleeMethodFullName)
}