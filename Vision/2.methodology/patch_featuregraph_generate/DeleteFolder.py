import os

def delete_java_files_not_in_org(deleted_jar):
    for root_dir, fileLst in deleted_jar.items():

        for dirpath, dirnames, filenames in os.walk(root_dir):
            for filename in filenames:

                file_path = os.path.join(dirpath, filename)

                flag = True

                for needsaveFile in fileLst:
                    if needsaveFile in file_path:
                        flag = False
                        break

                if flag:
                    os.remove(file_path)
                    print(f"Deleted file: {file_path}")

        gavFolders = get_subfolder_paths(root_dir)
        for gavFolder in gavFolders:
            for (root, dirs, files) in os.walk(gavFolder, topdown=False):
                for item in dirs:
                    dir = os.path.join(root, item)
                    try:
                        os.rmdir(dir)
                        print(dir)
                    except Exception as e:
                        pass

def get_subfolder_paths(folder):
    subfolders = []
    for root, dirs, files in os.walk(folder):
        for dir in dirs:
            subfolder_path = os.path.join(root, dir)
            subfolders.append(subfolder_path)
    return subfolders

deleted_jar = {
    "4.jar/jarDecompile/org.apache.wicket-wicket-core":[
        "/PackageResourceGuard.java"
    ],
    "4.jar/jarDecompile/org.springframework.data-spring-data-mongodb":[
        "/json/"
    ],
    "4.jar/jarDecompile/org.apache.logging.log4j-log4j-core":[
        "JmsManager.java", "JndiManager.java", "JndiContextSelector.java", "AbstractManager.java", "JmsManager.java", "Interpolator.java", "JndiLookup.java", "JndiContextSelector.java"
    ],
    "4.jar/jarDecompile/org.apache.hadoop-hadoop-common":[
        "/RunJar.java"
    ],
    "4.jar/jarDecompile/com.linecorp.armeria-armeria":[
        "HttpHeaderNames.java", "HttpHeadersBase.java", "ArmeriaHttpUtil.java", "ArmeriaHttpUtil.java", "PathAndQuery.java", "RoutingResultBuilder.java"
    ],
    "4.jar/jarDecompile/org.springframework.data-spring-data-rest-webmvc":[
        "AddOperation.java", "PatchOperation.java"
    ],
    "4.jar/jarDecompile/org.bouncycastle-bcprov-jdk15on":[
        "ASN1Integer.java", "ASN1StreamParser.java", "ConstructedOctetStream.java", "KeyPairGeneratorSpi.java", "Nat128.java", "Nat160.java", "Nat192.java", "Nat224.java", "Nat256.java", "ASN1Enumerated.java", "OpenBSDBCrypt.java", "DSASigner.java"
    ],
    "4.jar/jarDecompile/org.springframework.data-spring-data-commons":[
        "PropertyPath.java", "XmlBeamHttpMessageConverter.java", "SpringDataWebConfiguration.java"
    ],
    "4.jar/jarDecompile/org.codehaus.groovy-groovy":[
        "/MethodClosure.java"
    ],
    "4.jar/jarDecompile/org.apache.commons-commons-compress":[
        "ZipArchiveInputStream.java", "NioZipEncoding.java"
    ],
    "4.jar/jarDecompile/org.postgresql-postgresql":[
        "SimpleParameterList.java", "PgResultSet.java", "BCrypt.java"
    ],
    "4.jar/jarDecompile/org.springframework-spring-beans":[
        "CachedIntrospectionResults.java"
    ],
    "4.jar/jarDecompile/org.xwiki.commons-xwiki-commons-velocity":[
        "SecureIntrospector.java"
    ],
    "4.jar/jarDecompile/org.springframework.amqp-spring-amqp":[
        "/Message.java", 
    ],
}
delete_java_files_not_in_org(deleted_jar)