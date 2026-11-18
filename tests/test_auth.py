import os
import tempfile
import unittest
from unittest.mock import patch

from fastapi import HTTPException
from starlette.requests import Request
from starlette.responses import Response

from src import app as api
from src import auth


class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.environment = patch.dict(
            os.environ,
            {
                "USERS_DB_PATH": os.path.join(
                    self.temporary_directory.name, "users.sqlite"
                ),
                "ADMIN_EMAIL": "",
                "ADMIN_PASSWORD": "",
            },
        )
        self.environment.start()
        auth.initialize_auth_store()
        self.original_participants = api.activities["Chess Club"]["participants"]
        api.activities["Chess Club"]["participants"] = []

    def tearDown(self):
        api.activities["Chess Club"]["participants"] = self.original_participants
        self.environment.stop()
        self.temporary_directory.cleanup()

    def create_student(self, email="student@mergington.edu"):
        return auth.create_student_account(
            email, "correct-horse-battery-1", "Student Name", "11"
        )

    def test_login_and_logout_set_and_clear_secure_session_cookie(self):
        student = self.create_student()
        request = Request(
            {
                "type": "http",
                "asgi": {"version": "3.0"},
                "http_version": "1.1",
                "method": "POST",
                "scheme": "https",
                "path": "/auth/login",
                "raw_path": b"/auth/login",
                "query_string": b"",
                "headers": [],
                "server": ("testserver", 443),
                "client": ("testclient", 123),
            }
        )
        login_response = Response()

        result = api.login(
            api.LoginRequest(
                email=student.email, password="correct-horse-battery-1"
            ),
            request,
            login_response,
        )

        self.assertEqual(result["email"], student.email)
        self.assertIn("HttpOnly", login_response.headers["set-cookie"])
        self.assertIn("Secure", login_response.headers["set-cookie"])
        self.assertIn("SameSite=strict", login_response.headers["set-cookie"])
        session_token = login_response.headers["set-cookie"].split(";", 1)[0].split(
            "=", 1
        )[1]

        logout_response = Response()
        api.logout(request, logout_response, session_token)
        self.assertIn("school_session", logout_response.headers["set-cookie"])
        self.assertIn("Max-Age=0", logout_response.headers["set-cookie"])
        self.assertIsNone(auth.get_user_for_session(session_token))

    def test_student_profile_is_saved_and_password_is_hashed(self):
        student = self.create_student()

        self.assertEqual(student.public_data()["name"], "Student Name")
        self.assertEqual(student.grade, "11")
        self.assertIsNone(auth.authenticate_user(student.email, "wrong-password"))
        self.assertEqual(
            auth.authenticate_user(student.email, "correct-horse-battery-1"),
            student,
        )

        with auth._connection() as connection:
            row = connection.execute(
                "SELECT password_salt, password_hash FROM users WHERE email = ?",
                (student.email,),
            ).fetchone()
        self.assertNotEqual(row["password_hash"], "correct-horse-battery-1")

    def test_student_can_only_sign_up_and_unregister_self(self):
        student = self.create_student()
        api.signup_for_activity("Chess Club", student)
        self.assertEqual(
            api.activities["Chess Club"]["participants"],
            [student.email],
        )

        with self.assertRaises(HTTPException) as error:
            api.signup_for_activity(
                "Chess Club", student, "someone-else@mergington.edu"
            )
        self.assertEqual(error.exception.status_code, 403)

        with self.assertRaises(HTTPException) as error:
            api.unregister_from_activity(
                "Chess Club", student, "someone-else@mergington.edu"
            )
        self.assertEqual(error.exception.status_code, 403)

        api.unregister_from_activity("Chess Club", student)
        self.assertEqual(api.activities["Chess Club"]["participants"], [])

    def test_admin_can_manage_registration_for_student_account(self):
        with patch.dict(
            os.environ,
            {
                "ADMIN_EMAIL": "admin@mergington.edu",
                "ADMIN_PASSWORD": "a-strong-admin-password",
            },
        ):
            auth.initialize_auth_store()
            admin = auth.authenticate_user(
                "admin@mergington.edu", "a-strong-admin-password"
            )

        student = self.create_student()
        api.signup_for_activity("Chess Club", admin, student.email)
        self.assertEqual(
            api.activities["Chess Club"]["participants"],
            [student.email],
        )
        api.unregister_from_activity("Chess Club", admin, student.email)
        self.assertEqual(api.activities["Chess Club"]["participants"], [])

    def test_session_expires_and_unauthenticated_user_is_rejected(self):
        student = self.create_student()
        with patch("src.auth.time.time", return_value=1_000):
            token, expires_at = auth.create_session(student)
            self.assertEqual(auth.get_user_for_session(token), student)

        with patch("src.auth.time.time", return_value=expires_at + 1):
            self.assertIsNone(auth.get_user_for_session(token))

        with self.assertRaises(HTTPException) as error:
            api.get_current_user(None)
        self.assertEqual(error.exception.status_code, 401)


if __name__ == "__main__":
    unittest.main()
