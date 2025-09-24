# Flask 방명록 시스템 (XSS 취약점 포함)

Flask를 사용하여 Reflected XSS와 Stored XSS 취약점이 있는 방명록 시스템을 구현했습니다.

## 기능

- **메인 페이지 ('/')**: 검색 폼과 방명록 작성 폼
- **검색 기능 ('/search')**: Reflected XSS 취약점이 있는 검색 결과 출력
- **방명록 기능 ('/write')**: Stored XSS 취약점이 있는 방명록 저장 및 출력

## XSS 취약점

### Reflected XSS
<img width="1733" height="331" alt="Image" src="https://github.com/user-attachments/assets/9a3281ef-97b6-421d-9ac8-9a6d0d4836f3" />
- 검색 페이지에서 사용자 입력을 이스케이프 처리 없이 그대로 출력
- 악성 스크립트가 즉시 실행됨

### Stored XSS
- 방명록에 입력된 악성 스크립트가 서버에 저장됨
- 다른 사용자가 방명록을 볼 때마다 스크립트가 실행됨

## 실행 방법

```bash
python app.py
```

브라우저에서 `http://localhost:5000`으로 접속

## 파일 구조

```
week1/
├── app.py              # Flask 애플리케이션
├── templates/
│   └── index.html      # 메인 페이지 템플릿
└── README.md           # 이 파일
```
