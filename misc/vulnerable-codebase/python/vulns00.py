import flask
import re

app = flask.Flask(__name__)


@app.route('/realOne00', methods=['GET'])
def realOne00():
    # Real reflected XSS
    my_param = flask.request.args.get('my_param')
    content = f"<html><body>Hello {my_param}</body></html>"
    return content


@app.route('/fakeOne00', methods=['GET'])
def fakeOne00():
    # Fake reflected XSS
    my_param = flask.request.args.get('my_param')
    my_param = re.sub(r'[<>\'"]+', '', my_param)
    content = f"<html><body>Hello {my_param}</body></html>"
    return content


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
