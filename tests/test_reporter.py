"""Testes para helpers do relatório."""

import pathlib
import re
import unittest
from unittest.mock import patch

from rich.console import Console

from basiliskscan.reporter import ReportGenerator


class TestReporter(unittest.TestCase):
    """Valida a exibição de status e upgrade no relatório."""

    def setUp(self):
        self.reporter = ReportGenerator()

    def test_build_dependency_status_with_fixed_version(self):
        dep = {"name": "lodash", "version_spec": "4.17.20"}
        vulns = [{"id": "CVE-1", "fixed_version": "4.17.21"}]

        status = self.reporter._build_dependency_status(dep, vulns)

        self.assertTrue(status["is_vulnerable"])
        self.assertTrue(status["has_update"])
        self.assertEqual(status["recommended_version"], "4.17.21")
        labels = [badge["label"] for badge in status["badges"]]
        self.assertIn("Vulnerável", labels)
        self.assertIn("Atualização disponível", labels)

    def test_build_dependency_status_without_fixed_version(self):
        dep = {"name": "legacy-lib", "version_spec": "1.0.0"}
        vulns = [{"id": "CVE-1"}]

        status = self.reporter._build_dependency_status(dep, vulns)

        self.assertTrue(status["is_vulnerable"])
        self.assertFalse(status["has_update"])
        self.assertIsNone(status["recommended_version"])
        labels = [badge["label"] for badge in status["badges"]]
        self.assertEqual(labels, ["Vulnerável"])

    def test_build_dependency_status_secure_with_update(self):
        dep = {"name": "safe-lib", "version_spec": "1.0.0", "latest_version": "1.1.0"}

        status = self.reporter._build_dependency_status(dep, [])

        self.assertFalse(status["is_vulnerable"])
        self.assertTrue(status["has_update"])
        labels = [badge["label"] for badge in status["badges"]]
        self.assertIn("Seguro", labels)
        self.assertIn("Atualização disponível", labels)

    def test_build_vulnerable_components_groups_npm_manifest_and_lockfile(self):
        dependencies = [
            {
                "name": "express",
                "ecosystem": "npm",
                "version_spec": "^4.19.2",
                "declared_in": "C:/repo/backend/package.json",
            },
            {
                "name": "express",
                "ecosystem": "npm",
                "version_spec": "4.19.2",
                "declared_in": "C:/repo/backend/package-lock.json",
            },
        ]
        vulnerabilities_data = {
            "express": [
                {"id": "CVE-123", "severity": "HIGH"},
            ]
        }

        components = self.reporter._build_vulnerable_components(dependencies, vulnerabilities_data)

        self.assertEqual(len(components), 1)
        self.assertEqual(components[0]["name"], "express")
        self.assertIn("package.json", components[0]["declared_in"])
        self.assertIn("package-lock.json", components[0]["declared_in"])

    def test_build_vulnerable_components_keeps_different_project_scopes(self):
        dependencies = [
            {
                "name": "react-datepicker",
                "ecosystem": "npm",
                "version_spec": "^7.5.0",
                "declared_in": "C:/repo/backend/package.json",
            },
            {
                "name": "react-datepicker",
                "ecosystem": "npm",
                "version_spec": "^7.5.0",
                "declared_in": "C:/repo/frontend/package.json",
            },
        ]
        vulnerabilities_data = {
            "react-datepicker": [
                {"id": "CVE-XYZ", "severity": "MEDIUM"},
            ]
        }

        components = self.reporter._build_vulnerable_components(dependencies, vulnerabilities_data)

        self.assertEqual(len(components), 2)

    def test_build_grouped_dependencies_collapses_manifest_and_lockfile(self):
        dependencies = [
            {
                "name": "express",
                "ecosystem": "npm",
                "version_spec": "^4.19.2",
                "declared_in": "C:/repo/backend/package.json",
                "dependency_type": "direct",
                "is_transitive": False,
            },
            {
                "name": "express",
                "ecosystem": "npm",
                "version_spec": "4.19.2",
                "declared_in": "C:/repo/backend/package-lock.json",
                "dependency_type": "transitive",
                "is_transitive": True,
            },
        ]

        grouped = self.reporter._build_grouped_dependencies(dependencies)

        self.assertEqual(len(grouped), 1)
        self.assertEqual(grouped[0]["relationship"], "mixed")
        self.assertIn("package.json", grouped[0]["declared_in"])
        self.assertIn("package-lock.json", grouped[0]["declared_in"])

    def test_build_grouped_dependencies_marks_transitive_only(self):
        dependencies = [
            {
                "name": "body-parser",
                "ecosystem": "npm",
                "version_spec": "1.20.2",
                "declared_in": "C:/repo/backend/package-lock.json",
                "dependency_type": "transitive",
                "is_transitive": True,
            }
        ]

        grouped = self.reporter._build_grouped_dependencies(dependencies)

        self.assertEqual(len(grouped), 1)
        self.assertEqual(grouped[0]["relationship"], "transitive")

    def test_build_grouped_dependencies_preserves_latest_version_from_group(self):
        dependencies = [
            {
                "name": "express",
                "ecosystem": "npm",
                "version_spec": "4.19.2",
                "declared_in": "C:/repo/backend/package-lock.json",
                "dependency_type": "transitive",
                "is_transitive": True,
            },
            {
                "name": "express",
                "ecosystem": "npm",
                "version_spec": "^4.19.2",
                "declared_in": "C:/repo/backend/package.json",
                "dependency_type": "direct",
                "is_transitive": False,
                "latest_version": "4.21.0",
            },
        ]

        grouped = self.reporter._build_grouped_dependencies(dependencies)

        self.assertEqual(len(grouped), 1)
        self.assertEqual(grouped[0]["latest_version"], "4.21.0")

    def test_render_dependency_relationship_badge_contains_expected_label(self):
        direct_badge = self.reporter._render_dependency_relationship_badge({"relationship": "direct"})
        transitive_badge = self.reporter._render_dependency_relationship_badge({"relationship": "transitive"})
        mixed_badge = self.reporter._render_dependency_relationship_badge({"relationship": "mixed"})

        self.assertIn("Direta", direct_badge)
        self.assertIn("manifesto do projeto", direct_badge)
        self.assertIn("Transitiva", transitive_badge)
        self.assertIn("indiretamente", transitive_badge)
        self.assertIn("Mista", mixed_badge)
        self.assertIn("direta e também transitiva", mixed_badge)

    def test_render_status_badges_contains_expected_tooltips(self):
        status = self.reporter._build_dependency_status(
            {"name": "safe-lib", "version_spec": "1.0.0", "latest_version": "1.1.0"},
            [],
        )

        badges_html = self.reporter._render_status_badges(status)

        self.assertIn("Nenhuma vulnerabilidade conhecida", badges_html)
        self.assertIn("Existe uma versão mais recente ou corrigida", badges_html)

    def test_build_cvss_tooltip_contains_explanation_and_ranges(self):
        tooltip = self.reporter._build_cvss_tooltip(
            {
                "score": 9.2,
                "cvss": {"version": "4.0", "score": 9.2},
            }
        )

        self.assertIn("O que é CVSS?", tooltip)
        self.assertIn("CVSS v4.0", tooltip)
        self.assertIn("gravidade Crítico", tooltip)
        self.assertIn("CVSS v2.0", tooltip)
        self.assertIn("9,0-10,0", tooltip)
        self.assertIn('class="cvss-cell-active cvss-cell-active-critical">9,0-10,0', tooltip)

    def test_generate_html_report_counts_outdated_grouped_components(self):
        dependencies = [
            {
                "name": "express",
                "ecosystem": "npm",
                "version_spec": "4.19.2",
                "declared_in": "C:/repo/backend/package-lock.json",
                "dependency_type": "transitive",
                "is_transitive": True,
            },
            {
                "name": "express",
                "ecosystem": "npm",
                "version_spec": "^4.19.2",
                "declared_in": "C:/repo/backend/package.json",
                "dependency_type": "direct",
                "is_transitive": False,
                "latest_version": "4.21.0",
            },
        ]
        report_data = self.reporter.generate_report_data(
            target_path=pathlib.Path("C:/repo/backend"),
            dependencies=dependencies,
            ecosystems={"npm": 2},
            output_file="report.html",
            vulnerabilities={},
        )

        html = self.reporter.generate_html_report(report_data)

        self.assertIn('<div class="number">1</div>\n                        <div class="label">Componentes Desatualizados</div>', html)
        self.assertIn("Nenhuma vulnerabilidade conhecida", html)
        self.assertIn("Existe uma versão mais recente ou corrigida", html)

    def test_generate_html_report_renders_cvss_tooltip_and_path_class(self):
        dependencies = [
            {
                "name": "jspdf",
                "ecosystem": "npm",
                "version_spec": "2.5.2",
                "declared_in": "E:/Users/lucas/Desktop/Projeto Integrado I/2024-2-GestaoNutricionalIFSP/codigofonte/frontend/package-lock.json",
            }
        ]
        vulnerabilities = {
            "jspdf": [
                {
                    "id": "CVE-2025-68428",
                    "severity": "CRITICAL",
                    "score": 9.2,
                    "description": "Test vulnerability",
                    "fixed_version": "4.0.0",
                    "cvss": {"version": "4.0", "score": 9.2},
                }
            ]
        }
        report_data = self.reporter.generate_report_data(
            target_path=pathlib.Path("C:/repo/frontend"),
            dependencies=dependencies,
            ecosystems={"npm": 1},
            output_file="report.html",
            vulnerabilities=vulnerabilities,
        )

        html = self.reporter.generate_html_report(report_data)

        self.assertIn('class="tooltip tooltip-cvss"', html)
        self.assertIn('class="info-value path"', html)
        self.assertIn("O que é CVSS?", html)
        self.assertIn('id="vuln-type-filters"', html)
        self.assertIn('data-vuln-type-filter="all"', html)
        self.assertIn('data-vuln-type="security-issue"', html)
        self.assertIn('id="vuln-sort-select"', html)
        self.assertIn('id="vuln-severity-filter"', html)
        self.assertIn('id="vuln-search-input"', html)
        self.assertIn('id="vuln-results-summary"', html)
        self.assertIn('id="vuln-current-sort"', html)
        self.assertIn('id="vuln-cards-container"', html)
        self.assertIn('data-max-severity-score="4"', html)
        self.assertIn('data-vuln-count="1"', html)

    def test_generate_html_report_shows_transitive_hidden_note(self):
        dependencies = [
            {
                "name": "express",
                "ecosystem": "npm",
                "version_spec": "^4.19.2",
                "declared_in": "C:/repo/backend/package.json",
                "dependency_type": "direct",
                "is_transitive": False,
            }
        ]
        report_data = self.reporter.generate_report_data(
            target_path=pathlib.Path("C:/repo/backend"),
            dependencies=dependencies,
            ecosystems={"npm": 1},
            output_file="report.html",
            vulnerabilities={},
            report_options={"include_transitive": False, "transitive_hidden_count": 42},
        )

        html = self.reporter.generate_html_report(report_data)

        self.assertIn("dependência(s) transitiva(s) foram ocultadas", html)
        self.assertIn("--include-transitive", html)

    def test_generate_html_report_hides_transitive_hidden_note_when_zero(self):
        dependencies = [
            {
                "name": "express",
                "ecosystem": "npm",
                "version_spec": "^4.19.2",
                "declared_in": "C:/repo/backend/package.json",
                "dependency_type": "direct",
                "is_transitive": False,
            }
        ]
        report_data = self.reporter.generate_report_data(
            target_path=pathlib.Path("C:/repo/backend"),
            dependencies=dependencies,
            ecosystems={"npm": 1},
            output_file="report.html",
            vulnerabilities={},
            report_options={"include_transitive": False, "transitive_hidden_count": 0},
        )

        html = self.reporter.generate_html_report(report_data)

        self.assertNotIn("dependência(s) transitiva(s) foram ocultadas", html)

    def test_generate_report_data_uses_displayed_dependencies_count(self):
        displayed_dependencies = [
            {
                "name": "react",
                "ecosystem": "npm",
                "version_spec": "^18.0.0",
                "declared_in": "C:/repo/frontend/package.json",
                "dependency_type": "direct",
                "is_transitive": False,
            }
        ]
        all_dependencies = displayed_dependencies + [
            {
                "name": "scheduler",
                "ecosystem": "npm",
                "version_spec": "0.23.0",
                "declared_in": "C:/repo/frontend/package-lock.json",
                "dependency_type": "transitive",
                "is_transitive": True,
            }
        ]

        report_data = self.reporter.generate_report_data(
            target_path=pathlib.Path("C:/repo/frontend"),
            dependencies=displayed_dependencies,
            ecosystems={"npm": 1},
            output_file="report.html",
            vulnerabilities={},
            all_dependencies=all_dependencies,
            report_options={"include_transitive": False, "transitive_hidden_count": 1},
        )

        html = self.reporter.generate_html_report(report_data)

        self.assertEqual(report_data["project_info"]["dependency_count"], 1)
        self.assertIn('<i class="bi bi-box-seam"></i> Dependências (1)', html)
        self.assertIn('<div class="number">1</div>', html)

    def test_generate_html_report_overview_total_matches_grouped_tab_count(self):
        dependencies = [
            {
                "name": "axios",
                "ecosystem": "npm",
                "version_spec": "1.8.1",
                "declared_in": "C:/repo/backend/package.json",
                "dependency_type": "direct",
                "is_transitive": False,
            },
            {
                "name": "axios",
                "ecosystem": "npm",
                "version_spec": "1.8.1",
                "declared_in": "C:/repo/frontend/package.json",
                "dependency_type": "direct",
                "is_transitive": False,
            },
        ]

        report_data = self.reporter.generate_report_data(
            target_path=pathlib.Path("C:/repo"),
            dependencies=dependencies,
            ecosystems={"npm": 2},
            output_file="report.html",
            vulnerabilities={},
        )

        html = self.reporter.generate_html_report(report_data)

        tab_match = re.search(r"Dependências \((\d+)\)", html)
        card_match = re.search(
            r'<div class="number">(\d+)</div>\s*<div class="label">Total de Dependências</div>',
            html,
        )

        self.assertIsNotNone(tab_match)
        self.assertIsNotNone(card_match)
        self.assertEqual(tab_match.group(1), card_match.group(1))

    @patch("webbrowser.open", return_value=False)
    def test_display_scan_results_uses_grouped_count(self, _mock_webbrowser_open):
        console = Console(record=True, force_terminal=False, width=140)
        reporter = ReportGenerator(console=console)

        dependencies = [
            {
                "name": "axios",
                "ecosystem": "npm",
                "version_spec": "1.8.1",
                "declared_in": "C:/repo/backend/package.json",
                "dependency_type": "direct",
                "is_transitive": False,
            },
            {
                "name": "axios",
                "ecosystem": "npm",
                "version_spec": "1.8.1",
                "declared_in": "C:/repo/backend/package-lock.json",
                "dependency_type": "transitive",
                "is_transitive": True,
            },
        ]

        reporter.display_scan_results(
            dependencies=dependencies,
            ecosystems={"npm": 2},
            output_file="report.html",
            vulnerabilities={},
        )

        output = console.export_text()
        self.assertRegex(output, r"\b1\b dependências encontradas")
        self.assertIn("2 ocorrência(s) bruta(s) no parse", output)

    @patch("basiliskscan.reporter.GoogleTranslator")
    def test_translate_text_preserves_technical_terms(self, mock_translator_cls):
        mock_translator = mock_translator_cls.return_value

        def fake_translate(text: str) -> str:
            return (
                text
                .replace("security issue", "problema de segurança")
                .replace("allows", "permite")
                .replace("JavaScript", "Javascript")
                .replace("TypeScript", "TipoScript")
                .replace("Rust", "Enferrujado")
                .replace("rust", "enferrujada")
                .replace("node", "nó")
                .replace("Next.js", "Próximo.js")
                .replace("npm", "gerenciador")
                .replace("package", "pacote")
                .replace("lockfile", "arquivo de bloqueio")
                .replace("crate", "caixote")
                .replace("Go", "Ir")
                .replace("JWT", "TokenWebJson")
                .replace("jsonwebtoken", "tokenwebjson")
                .replace("activate_nbf", "ativar_nbf")
                .replace("require_spec_claims", "reivindicacoes_especificas")
            )

        mock_translator.translate.side_effect = fake_translate

        translated = self.reporter._translate_text(
            "This security issue allows code execution in JavaScript, TypeScript, Rust, node and Next.js with npm package lockfile crate and Go."
        )

        self.assertIn("JavaScript", translated)
        self.assertIn("TypeScript", translated)
        self.assertIn("Rust", translated)
        self.assertIn("node", translated)
        self.assertIn("Next.js", translated)
        self.assertIn("npm", translated)
        self.assertIn("package", translated)
        self.assertIn("lockfile", translated)
        self.assertIn("crate", translated)
        self.assertIn("Go", translated)
        self.assertNotIn("Enferrujado", translated)
        self.assertNotIn("nó runtimes", translated)
        self.assertNotIn("TipoScript", translated)
        self.assertNotIn("Próximo.js", translated)
        self.assertNotIn("arquivo de bloqueio", translated)

        translated_real_case = self.reporter._translate_text(
            "jsonwebtoken is a JWT rust library. If activate_nbf is enabled and require_spec_claims is not required, FailedToParse is treated like NotPresent for nbf and exp."
        )

        self.assertIn("jsonwebtoken", translated_real_case)
        self.assertIn("JWT", translated_real_case)
        self.assertIn("rust", translated_real_case)
        self.assertIn("activate_nbf", translated_real_case)
        self.assertIn("require_spec_claims", translated_real_case)
        self.assertIn("FailedToParse", translated_real_case)
        self.assertIn("NotPresent", translated_real_case)
        self.assertNotIn("enferrujada", translated_real_case)
        self.assertNotIn("TokenWebJson", translated_real_case)
        self.assertNotIn("tokenwebjson", translated_real_case)


if __name__ == "__main__":
    unittest.main()