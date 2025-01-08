from flask import Flask, jsonify
from flask_httpauth import HTTPBasicAuth

app = Flask(__name__)
auth = HTTPBasicAuth()

students=[
  {"roll_no": 1, "name": "mitakshya", "age": 20},
  {"roll_no": 2, "name": "prasamsha", "age": 20},
  {"roll_no": 3, "name": "aashriya", "age": 20},
  {"roll_no": 4, "name": "bidhya", "age": 20}
]

users = {
  "mitaskhya": "7777",
  "prasamsha": "5555"
}

@auth.verify_password
def verify_password(username, password):
  if username in users and users[username] == password:
    return username

@app.route('/students', methods =['GET'])
@auth.login_required
def get_students():
  return jsonify({"message": f"hello,{auth.current_user()}", "students": students})

@app.route('/students/<int:roll_no>', methods =['GET'])
@auth.login_required
def get_student(roll_no):
  for student in students:
    if student['roll_no'] == roll_no:
      return jsonify(student)
  return jsonify({"message":"student not found"})

  

if __name__ == '__main__':
  app.run(debug=True)