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
    cpg.method(methodName).filter(node=>node.lineNumber==Some(value=line)).ast.inAstMinusLeaf.isCall.name(".*logicalNot.*").map(node=>(node.code,node.lineNumber)).toJson |> "conditionJson/CONDITION"+cnt.toString+".json"
    cpg.method(methodName).filter(node=>node.lineNumber==Some(value=line)).ast.inAstMinusLeaf.isCall.name(".*greaterEqualsThan.*").map(node=>(node.code,node.lineNumber)).toJson |> "conditionJson/GET"+cnt.toString+".json"
    cpg.method(methodName).filter(node=>node.lineNumber==Some(value=line)).ast.inAstMinusLeaf.isCall.name(".*lessEqualsThan.*").map(node=>(node.code,node.lineNumber)).toJson |> "conditionJson/LET"+cnt.toString+".json"

    cnt+=1
  })
}