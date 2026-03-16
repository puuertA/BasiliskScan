"""
Testes para o módulo de ingestão de vulnerabilidades.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from basiliskscan.ingest import (
    NVDClient,
    OSSIndexClient,
    VulnerabilityNormalizer,
    Severity
)


class TestNVDClient(unittest.TestCase):
    """Testes para o cliente NVD."""
    
    def setUp(self):
        """Configura o cliente para testes."""
        self.client = NVDClient()
    
    def test_initialization(self):
        """Testa inicialização do cliente."""
        self.assertIsNone(self.client.api_key)
        self.assertEqual(self.client.get_source_name(), "NVD")
    
    def test_initialization_with_api_key(self):
        """Testa inicialização com API key."""
        client = NVDClient(api_key="test-key")
        self.assertEqual(client.api_key, "test-key")
        self.assertEqual(client.request_interval, client.REQUEST_INTERVAL_WITH_KEY)
    
    @patch('basiliskscan.ingest.nvd.requests.Session.get')
    def test_fetch_vulnerabilities(self, mock_get):
        """Testa busca de vulnerabilidades."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulnerabilities": [
                {"cve": {"id": "CVE-2021-44228"}}
            ]
        }
        mock_get.return_value = mock_response
        
        vulns = self.client.fetch_vulnerabilities("log4j")
        
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0]["cve"]["id"], "CVE-2021-44228")
    
    @patch('basiliskscan.ingest.nvd.requests.Session.get')
    def test_fetch_cve_by_id(self, mock_get):
        """Testa busca de CVE por ID."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulnerabilities": [
                {"cve": {"id": "CVE-2021-44228"}}
            ]
        }
        mock_get.return_value = mock_response
        
        cve = self.client.fetch_cve_by_id("CVE-2021-44228")
        
        self.assertIsNotNone(cve)
        self.assertEqual(cve["cve"]["id"], "CVE-2021-44228")


class TestOSSIndexClient(unittest.TestCase):
    """Testes para o cliente OSS Index."""
    
    def setUp(self):
        """Configura o cliente para testes."""
        self.client = OSSIndexClient()
    
    def test_initialization(self):
        """Testa inicialização do cliente."""
        self.assertIsNone(self.client.api_key)
        self.assertEqual(self.client.get_source_name(), "OSS Index")
    
    def test_build_purl_npm(self):
        """Testa construção de purl para npm."""
        purl = self.client._build_purl("express", "4.17.1", "npm")
        self.assertEqual(purl, "pkg:npm/express@4.17.1")
    
    def test_build_purl_maven(self):
        """Testa construção de purl para maven."""
        purl = self.client._build_purl(
            "org.springframework:spring-core", 
            "5.2.0", 
            "maven"
        )
        self.assertEqual(purl, "pkg:maven/org.springframework/spring-core@5.2.0")
    
    def test_build_purl_pypi(self):
        """Testa construção de purl para pypi."""
        purl = self.client._build_purl("requests", "2.28.0", "pypi")
        self.assertEqual(purl, "pkg:pypi/requests@2.28.0")
    
    @patch('basiliskscan.ingest.oss_index.requests.Session.post')
    def test_fetch_by_purl(self, mock_post):
        """Testa busca por purl."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {
                "coordinates": "pkg:npm/express@4.17.1",
                "vulnerabilities": []
            }
        ]
        mock_post.return_value = mock_response
        
        results = self.client.fetch_by_purl(["pkg:npm/express@4.17.1"])
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["coordinates"], "pkg:npm/express@4.17.1")


class TestVulnerabilityNormalizer(unittest.TestCase):
    """Testes para o normalizador de vulnerabilidades."""
    
    def test_normalize_severity(self):
        """Testa normalização de severidade."""
        self.assertEqual(
            VulnerabilityNormalizer._normalize_severity("CRITICAL"),
            Severity.CRITICAL.value
        )
        self.assertEqual(
            VulnerabilityNormalizer._normalize_severity("high"),
            Severity.HIGH.value
        )
        self.assertEqual(
            VulnerabilityNormalizer._normalize_severity("MODERATE"),
            Severity.MEDIUM.value
        )
    
    def test_score_to_severity(self):
        """Testa conversão de score para severidade."""
        self.assertEqual(
            VulnerabilityNormalizer._score_to_severity(10.0),
            Severity.CRITICAL.value
        )
        self.assertEqual(
            VulnerabilityNormalizer._score_to_severity(8.5),
            Severity.HIGH.value
        )
        self.assertEqual(
            VulnerabilityNormalizer._score_to_severity(5.0),
            Severity.MEDIUM.value
        )
        self.assertEqual(
            VulnerabilityNormalizer._score_to_severity(2.0),
            Severity.LOW.value
        )
    
    def test_normalize_nvd_vulnerability(self):
        """Testa normalização de vulnerabilidade do NVD."""
        nvd_data = {
            "cve": {
                "id": "CVE-2021-44228",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "Apache Log4j2 RCE vulnerability"
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                "baseScore": 10.0,
                                "baseSeverity": "CRITICAL"
                            }
                        }
                    ]
                },
                "published": "2021-12-10T10:15:09.000",
                "lastModified": "2022-01-05T18:15:08.000",
                "references": [],
                "weaknesses": []
            }
        }
        
        normalized = VulnerabilityNormalizer.normalize_nvd_vulnerability(nvd_data)
        
        self.assertEqual(normalized["id"], "CVE-2021-44228")
        self.assertEqual(normalized["source"], "NVD")
        self.assertEqual(normalized["severity"], Severity.CRITICAL.value)
        self.assertEqual(normalized["score"], 10.0)
        self.assertIn("Apache Log4j2", normalized["description"])
    
    def test_normalize_oss_index_vulnerability(self):
        """Testa normalização de vulnerabilidade do OSS Index."""
        component_data = {
            "coordinates": "pkg:npm/express@4.17.1",
            "description": "Fast, unopinionated, minimalist web framework"
        }
        
        vuln_data = {
            "id": "sonatype-2021-1234",
            "title": "Denial of Service",
            "description": "Express DoS vulnerability",
            "cvssScore": 7.5,
            "cvssVector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            "cve": "CVE-2021-1234",
            "reference": "https://example.com/advisory"
        }
        
        normalized = VulnerabilityNormalizer.normalize_oss_index_vulnerability(
            component_data, vuln_data
        )
        
        self.assertEqual(normalized["id"], "CVE-2021-1234")
        self.assertEqual(normalized["source"], "OSS Index")
        self.assertEqual(normalized["severity"], Severity.HIGH.value)
        self.assertEqual(normalized["score"], 7.5)
    
    def test_merge_vulnerabilities(self):
        """Testa mesclagem de vulnerabilidades."""
        vuln1 = {
            "id": "CVE-2021-44228",
            "source": "NVD",
            "severity": Severity.CRITICAL.value,
            "score": 10.0,
            "cvss": {},
            "references": [{"url": "https://nvd.nist.gov", "source": "NVD", "tags": []}],
            "affected_products": []
        }
        
        vuln2 = {
            "id": "CVE-2021-44228",
            "source": "OSS Index",
            "severity": Severity.HIGH.value,
            "score": 9.0,
            "cvss": {},
            "references": [{"url": "https://ossindex.sonatype.org", "source": "OSS", "tags": []}],
            "affected_products": []
        }
        
        merged = VulnerabilityNormalizer.merge_vulnerabilities([vuln1, vuln2])
        
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["id"], "CVE-2021-44228")
        self.assertIn("NVD", merged[0]["sources"])
        self.assertIn("OSS Index", merged[0]["sources"])
        # Deve manter a severidade mais alta (CRITICAL)
        self.assertEqual(merged[0]["severity"], Severity.CRITICAL.value)
        # Deve mesclar referências
        self.assertEqual(len(merged[0]["references"]), 2)

if __name__ == "__main__":
    unittest.main()
