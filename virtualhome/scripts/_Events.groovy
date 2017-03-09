eventCreateWarStart = { name, stagingDir ->
  ant.delete(dir:"${stagingDir}/WEB-INF/lib/", includes: "groovy-all-2.0.8.jar", verbose: true)
}
