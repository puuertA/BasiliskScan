"""Testes para o parser de dependências Java."""

import tempfile
import unittest
import shutil
from pathlib import Path

from basiliskscan.parsers.java import JavaParser


class TestJavaParser(unittest.TestCase):
    """Garante cobertura básica para Maven e Gradle."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.parser = JavaParser()

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_parse_maven_with_namespace(self):
        pom_file = self.temp_dir / "pom.xml"
        pom_file.write_text(
            """<project xmlns=\"http://maven.apache.org/POM/4.0.0\">
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-web</artifactId>
      <version>6.1.5</version>
    </dependency>
  </dependencies>
</project>""",
            encoding="utf-8",
        )

        dependencies = self.parser.parse(pom_file)

        self.assertEqual(len(dependencies), 1)
        self.assertEqual(dependencies[0]["name"], "org.springframework:spring-web")
        self.assertEqual(dependencies[0]["version_spec"], "6.1.5")
        self.assertEqual(dependencies[0]["scope"], "compile")
        self.assertEqual(dependencies[0]["dependency_type"], "direct")
        self.assertFalse(dependencies[0]["is_transitive"])
        self.assertEqual(
            dependencies[0]["purl"],
            "pkg:maven/org.springframework/spring-web@6.1.5",
        )

    def test_parse_maven_without_namespace(self):
        pom_file = self.temp_dir / "pom.xml"
        pom_file.write_text(
            """<project>
  <dependencies>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
</project>""",
            encoding="utf-8",
        )

        dependencies = self.parser.parse(pom_file)

        self.assertEqual(len(dependencies), 1)
        self.assertEqual(dependencies[0]["name"], "junit:junit")
        self.assertEqual(dependencies[0]["version_spec"], "4.13.2")
        self.assertEqual(dependencies[0]["scope"], "test")

    def test_parse_gradle_string_and_map_notation(self):
        gradle_file = self.temp_dir / "build.gradle"
        gradle_file.write_text(
            """plugins {
    id 'java'
}

dependencies {
    implementation 'org.springframework:spring-web:6.1.5'
    testImplementation "junit:junit:4.13.2"
    runtimeOnly group: 'mysql', name: 'mysql-connector-java', version: '8.0.33'
}
""",
            encoding="utf-8",
        )

        dependencies = self.parser.parse(gradle_file)

        self.assertEqual(len(dependencies), 3)
        self.assertEqual(dependencies[0]["name"], "org.springframework:spring-web")
        self.assertEqual(dependencies[0]["scope"], "implementation")
        self.assertEqual(dependencies[1]["name"], "junit:junit")
        self.assertEqual(dependencies[1]["scope"], "testImplementation")
        self.assertEqual(dependencies[2]["name"], "mysql:mysql-connector-java")
        self.assertEqual(dependencies[2]["scope"], "runtimeOnly")
        self.assertEqual(
            dependencies[0]["purl"],
            "pkg:maven/org.springframework/spring-web@6.1.5",
        )

    def test_parse_gradle_kotlin_named_arguments(self):
        gradle_file = self.temp_dir / "build.gradle.kts"
        gradle_file.write_text(
            """dependencies
{
    implementation(group = "org.hibernate", name = "hibernate-core", version = "6.4.4.Final")
}
""",
            encoding="utf-8",
        )

        dependencies = self.parser.parse(gradle_file)

        self.assertEqual(len(dependencies), 1)
        self.assertEqual(dependencies[0]["name"], "org.hibernate:hibernate-core")
        self.assertEqual(dependencies[0]["version_spec"], "6.4.4.Final")
        self.assertEqual(dependencies[0]["scope"], "implementation")

    def test_parse_ant_netbeans_project_properties(self):
        build_file = self.temp_dir / "build.xml"
        build_file.write_text("<project name=\"demo\"/>", encoding="utf-8")

        nbproject_dir = self.temp_dir / "nbproject"
        nbproject_dir.mkdir()
        (nbproject_dir / "project.properties").write_text(
            """file.reference.log4j-api-2.17.1.jar=lib\\log4j-api-2.17.1.jar
file.reference.mysql-connector-java-8.0.20.jar=lib/mysql-connector-java-8.0.20.jar
javac.classpath=${file.reference.log4j-api-2.17.1.jar}:${file.reference.mysql-connector-java-8.0.20.jar}
""",
            encoding="utf-8",
        )

        dependencies = self.parser.parse(build_file)

        self.assertEqual(len(dependencies), 2)
        self.assertEqual(dependencies[0]["ecosystem"], "ant")
        self.assertEqual(dependencies[0]["name"], "log4j-api")
        self.assertEqual(dependencies[0]["version_spec"], "2.17.1")
        self.assertEqual(dependencies[1]["name"], "mysql-connector-java")
        self.assertEqual(dependencies[1]["version_spec"], "8.0.20")
        self.assertEqual(dependencies[0]["purl"], "pkg:generic/log4j-api@2.17.1")

    def test_parse_gradle_lockfile_as_transitive_dependencies(self):
        lockfile = self.temp_dir / "gradle.lockfile"
        lockfile.write_text(
            """# This is a Gradle generated file
org.springframework:spring-core:6.1.6=compileClasspath,runtimeClasspath
ch.qos.logback:logback-classic:1.4.14=runtimeClasspath
""",
            encoding="utf-8",
        )

        dependencies = self.parser.parse(lockfile)

        self.assertEqual(len(dependencies), 2)
        spring_core = next(dep for dep in dependencies if dep["name"] == "org.springframework:spring-core")
        self.assertEqual(spring_core["dependency_type"], "transitive")
        self.assertTrue(spring_core["is_transitive"])
        self.assertEqual(spring_core["scope"], "compileClasspath")
        self.assertEqual(
            spring_core["purl"],
            "pkg:maven/org.springframework/spring-core@6.1.6",
        )


if __name__ == "__main__":
    unittest.main()