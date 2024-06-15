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
    cpg.method(methodName).filter(node=>(node.lineNumber==Some(value=line))).dotPdg.toJson|>"slicingJson/PDG"+cnt.toString+".json"
	  cpg.method(methodName).filter(node=>(node.lineNumber==Some(value=line))).ast.isCall.filter(node=>node.methodFullName=="<operator>.assignment").map(node=>node.lineNumber).toJson|>"slicingJson/assignment"+cnt.toString+".json"
	  cpg.method(methodName).filter(node=>(node.lineNumber==Some(value=line))).ast.isControlStructure.filter(node=>node.controlStructureType=="IF").map(node=>(node.lineNumber)).toJson|>"slicingJson/control"+cnt.toString+".json"
	  cpg.method(methodName).filter(node=>(node.lineNumber==Some(value=line))).ast.isReturn.map(node=>node.lineNumber).toJson|>"slicingJson/return"+cnt.toString+".json"
    cnt+=1
  })
}