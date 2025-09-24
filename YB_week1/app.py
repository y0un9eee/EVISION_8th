from flask import Flask, request, render_template, redirect, url_for
from datetime import datetime

app = Flask(__name__)

# 간단한 메모리 기반 데이터베이스 (방명록 저장용)
guestbook_entries = []

@app.route('/')
def home():
    """메인 페이지: 검색 폼과 방명록 작성 폼을 포함"""
    #서버에서 guestbook_entries 리스트를 entries라는 이름으로 HTML에 전달
    return render_template('index.html', entries=guestbook_entries)

@app.route('/search')
def search():
    """검색 기능: Reflected XSS 취약점이 있는 검색 결과 출력"""
    query = request.args.get('q', '')
    # Reflected XSS 취약점: 사용자 입력을 그대로 출력!! (이스케이프 처리 안함)
    return f"<h1>검색 결과</h1><p>검색어: {query}</p><a href='/'>돌아가기</a>"

@app.route('/write', methods=['POST'])
def write_guestbook():
    """방명록 작성 기능: Stored XSS 취약점이 있는 방명록 저장"""
    name = request.form.get('name', '')
    message = request.form.get('message', '')
    
    if name and message:
        # Stored XSS 취약점: 사용자 입력을 그대로 저장!!(검증/이스케이프 처리 안함)
        entry = {
            'id': len(guestbook_entries) + 1,
            'name': name,
            'message': message
        }
        guestbook_entries.append(entry)
    
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
