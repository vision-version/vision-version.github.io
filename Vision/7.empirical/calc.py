import json

import git

data_path = "trueresult original.json"
info_path = "versions.json"

with open(data_path) as f:
    data = json.load(f)
with open(info_path) as f:
    info = json.load(f)


def format_tag(cveid: str, git_repo: str, tag: str) -> str:
    tag = tag.strip().lower()
    if git_repo.endswith("apache__fdse__maven-shared-utils"):
        tag = tag.replace("maven-shared-utils-", "")
    elif git_repo.endswith("FasterXML__fdse__jackson-databind"):
        tag = tag.replace("jackson-databind-", "")
    elif git_repo.endswith("dom4j__fdse__dom4j"):
        tag = tag.replace("dom4j_", "").replace(
            "dom4j-", "").replace("version-", "").replace("_", ".")
    elif git_repo.endswith("junrar__fdse__junrar"):
        tag = tag.replace("junrar-", "").replace("v", "")
    elif git_repo.endswith("apache__fdse__commons-fileupload"):
        tag = tag.replace("commons-fileupload-", "").replace("fileupload_", "").replace("_", "")
    elif git_repo.endswith("apache__fdse__xmlgraphics-commons"):
        tag = tag.replace("commons-", "").replace("_", ".")
    elif git_repo.endswith("netty__fdse__netty"):
        tag = tag.replace("netty-", "")
    elif git_repo.endswith("alibaba__fdse__fastjson") or git_repo.endswith("apache__fdse__httpcomponents-client"):
        tag = tag.replace("rel/v", "")
    elif git_repo.endswith("apache__fdse__poi"):
        tag = tag.replace("rel_", "")
    elif git_repo.endswith("OWASP__fdse__json-sanitizer"):
        tag = tag.replace("release-", "").replace("json-sanitizer-", "")
    elif git_repo.endswith("apache__fdse__commons-beanutils"):
        tag = tag.replace("commons-beanutils-", "").replace("beanutils_", "")
    elif git_repo.endswith("codehaus-plexus__fdse__plexus-utils"):
        tag = tag.replace("plexus-utils-", "")
    elif git_repo.endswith("apache__fdse__cxf"):
        tag = tag.replace("cxf-", "")
    elif git_repo.endswith("junit-team__fdse__junit4"):
        tag = tag.replace("r", "")
    elif git_repo.endswith("Bedework__fdse__bw-webdav"):
        tag = tag.replace("bw-webda-", "").replace("bw-webda", "").replace("-", "")
    elif git_repo.endswith("hunterhacker__fdse__jdom"):
        tag = tag.replace("jdom-", "")
    elif git_repo.endswith("xerial__fdse__snappy-java"):
        tag = tag.replace("snappy-jaa-", "")
    elif git_repo.endswith("apache__fdse__sling-org-apache-sling-api"):
        tag = tag.replace("org.apache.sling.api-", "")
    elif git_repo.endswith("apache__fdse__commons-configuration"):
        tag = tag.replace("configuration_", "").replace(
            "rel/commons-configuration-", "").replace("commons-configuration-", "")
    elif git_repo.endswith("json-path__fdse__JsonPath"):
        tag = tag.replace("json-path-parent-", "").replace("json-path-", "")
    elif git_repo.endswith("apache__fdse__james-project"):
        tag = tag.replace("james-project-", "")
    elif git_repo.endswith("apache__fdse__commons-compress"):
        tag = tag.replace("rel/commons-compress-", "").replace("commons-compress-",
                                                               "").replace("compress-", "").replace("rel/", "")
    elif git_repo.endswith("line__fdse__armeria"):
        tag = tag.replace("armeria-", "")
    elif git_repo.endswith("pgjdbc__fdse__pgjdbc"):
        tag = tag.replace("rel", "")
    elif git_repo.endswith("FasterXML__fdse__jackson-dataformat-xml"):
        tag = tag.replace("jackson-dataformat-xml-", "")
    elif git_repo.endswith("square__fdse__retrofit"):
        tag = tag.replace("parent-", "")
    elif git_repo.endswith("apache__fdse__struts"):
        tag = tag.replace("struts_", "")
    elif git_repo.endswith("socketio__fdse__socket.io-client-java"):
        tag = tag.replace("socket.io-client-", "")
    elif git_repo.endswith("xwiki__fdse__xwiki-commons"):
        tag = tag.replace("xwiki-commons-", "")
    elif git_repo.endswith("apache__fdse__wicket"):
        tag = tag.replace("rel/wicket-", "").replace("wicket-", "")
    elif git_repo.endswith("apache__fdse__groovy"):
        tag = tag.replace("grooy_", "").replace("_", ".").replace("groovy.", "")
    elif git_repo.endswith("apache__fdse__logging-log4j2"):
        tag = tag.replace("rel/", "").replace("log4j-", "")
    elif git_repo.endswith("bcgit__fdse__bc-java"):
        tag = tag.replace("r1", "1.").replace("r", "")
    elif git_repo.replace("apereo__fdse__java-cas-client", ""):
        tag = tag.replace("cas-client-", "")
    return tag.replace("v", "").replace("_", ".")


num = 0
result_dict = {}
reuslt_dict = {}

totol_jar = set()
same = set()
overlap = set()
disjoint = set()
jar_contains_repo = set()
repo_contains_jar = set()

all_rem_jar_versions = set()
all_rem_repo_tags = set()
all_jar_versions = set()
all_repo_tags = set()

for cveid, cve_data in data.items():
    jar_versions = []
    for jar_v in cve_data["affected"] + cve_data["unaffected"]:
        jar_versions.append(jar_v.lower())
    git_repo = info[cveid]["GitHubRepoPath"]
    jar_path = info[cveid]["JarDownloadPath"]
    repo_tags = []
    for tag in git.Repo(git_repo).tags:
        repo_tags.append(format_tag(cveid, git_repo, tag.name))
    jar_versions_set = set(jar_versions)
    repo_tags_set = set(repo_tags)
    overlap_set = jar_versions_set & repo_tags_set
    result_dict[jar_path] = {}
    result_dict[jar_path]["overlap"] = len(overlap_set)
    result_dict[jar_path]["jar_more"] = len(jar_versions_set - overlap_set)
    result_dict[jar_path]["repo_more"] = len(repo_tags_set - overlap_set)

    all_rem_jar_versions = all_rem_jar_versions | (jar_versions_set - overlap_set)
    all_rem_repo_tags = all_rem_repo_tags | (repo_tags_set - overlap_set)
    all_jar_versions = all_jar_versions | jar_versions_set
    all_repo_tags = all_repo_tags | repo_tags_set

    totol_jar.add(jar_path)
    if len(jar_versions_set - overlap_set) == 0 and len(repo_tags_set - overlap_set) == 0 and len(overlap_set) > 0:
        same.add(jar_path)
    elif len(jar_versions_set - overlap_set) > 0 and len(repo_tags_set - overlap_set) > 0 and len(overlap_set) > 0:
        overlap.add(jar_path)
        print("overlap:")
        print(f"jar_path: {jar_path}")
        print(f"jar_versions: {jar_versions_set}")
        print(f"repo_tags: {repo_tags_set}")
        print(f"jar_more: {jar_versions_set - overlap_set}")
        print(f"repo_more: {repo_tags_set - overlap_set}")
    elif len(jar_versions_set - overlap_set) > 0 and len(repo_tags_set - overlap_set) > 0 and len(overlap_set) == 0:
        disjoint.add(jar_path)
        print("disjoint:")
        print(f"jar_path: {jar_path}")
        print(f"jar_versions: {jar_versions_set}")
        print(f"repo_tags: {repo_tags_set}")
    elif len(jar_versions_set - overlap_set) > 0 and len(repo_tags_set - overlap_set) == 0 and len(overlap_set) > 0:
        jar_contains_repo.add(jar_path)
        print("jar_contains_repo:")
        print(f"jar_path: {jar_path}")
        print(f"jar_versions: {jar_versions_set}")
        print(f"repo_tags: {repo_tags_set}")
        print(f"jar_more: {jar_versions_set - overlap_set}")
        print(f"repo_more: {repo_tags_set - overlap_set}")
    elif len(jar_versions_set - overlap_set) == 0 and len(repo_tags_set - overlap_set) > 0 and len(overlap_set) > 0:
        repo_contains_jar.add(jar_path)
        print("repo_contains_jar:")
        print(f"jar_path: {jar_path}")
        print(f"jar_versions: {jar_versions_set}")
        print(f"repo_tags: {repo_tags_set}")
        print(f"jar_more: {jar_versions_set - overlap_set}")
        print(f"repo_more: {repo_tags_set - overlap_set}")
    else:
        print("error!!!!!!!!")
print("same:", len(same))
print("overlap:", len(overlap))
print("disjoint:", len(disjoint))
print("jar_contains_repo:", len(jar_contains_repo))
print("repo_contains_jar:", len(repo_contains_jar))
print("diff rate:", (len(totol_jar) - len(same)) / len(totol_jar))
print("total jar:", len(totol_jar))

print("all_rem_jar_versions:", len(all_rem_jar_versions))
print("all_rem_repo_tags:", len(all_rem_repo_tags))
print("all_jar_versions:", len(all_jar_versions))
print("all_repo_tags:", len(all_repo_tags))
