import com.google.gson._;
import java.io._;
@main def exec(cpgFile: String,filePath:String){
  importCpg(cpgFile);
  var jsonParser=new JsonParser();
  var jsonObject=jsonParser.parse(new FileReader(filePath));
  var list=jsonObject.getAsJsonArray;
  var cnt=0
  list.forEach(ja=>{
    var jsonObj=ja.getAsJsonObject();
    var signature=jsonObj.get("signature").getAsString();
    var line=jsonObj.get("lineNumber").getAsInt();
    var array1=signature.split("\\(")(0).split(" ")
    var methodName=array1(array1.length-1)
    cpg.method(methodName).filter(node=>(node.lineNumber==Some(value=line))).ast.isIdentifier.filter(node=>(cpg.method(methodName).filter(node=>(node.lineNumber==Some(value=line))).ast.isParameter.name.l.contains(node.name))).map(node=>(node.code,node.lineNumber,node.columnNumber)).toJson|>"normalizeJson/FP"+cnt.toString+".json"
    (cpg.method(methodName).filter(node=>(node.lineNumber==Some(value=line))).ast.isIdentifier.filterNot(node=>(cpg.method(methodName).filter(node=>(node.lineNumber==Some(value=line))).ast.isParameter.name.l.contains(node.name))).map(node=>(node.code,node.lineNumber,node.columnNumber)).toSet++cpg.method(methodName).filter(node=>(node.lineNumber==Some(value=line))).ast.isLocal.map(node=>(node.name,node.lineNumber,node.columnNumber)).toSet).l|>"normalizeJson/LV"+cnt.toString+".json"
    cpg.method(methodName).filter(node=>(node.lineNumber==Some(value=line))).ast.isLocal.map(node=>(node.code,node.name,node.typeFullName,node.lineNumber,node.columnNumber)).toJson|>"normalizeJson/DT"+cnt.toString+".json"
    cpg.method(methodName).filter(node=>(node.lineNumber==Some(value=line))).ast.isCall.filterNot(node=>(node.methodFullName.matches("<operator>.*")||(node.methodFullName.matches("<operators>.*")))).map(node=>(node.name,node.lineNumber,node.columnNumber)).toJson|>"normalizeJson/FC"+cnt.toString+".json"
    cpg.method(methodName).filter(node=>(node.lineNumber==Some(value=line))).ast.isLiteral.filter(node=>node.typeFullName=="char").map(node=>(node.code,node.lineNumber,node.columnNumber)).toJson|>"normalizeJson/STRING"+cnt.toString+".json"
    cnt+=1
  })
}