class CustomError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }

  getStatus() {
    return this.status;
  }
}

class AuthenticationError extends CustomError {
  constructor(message) {
    super(message, 401);
  }
}

export default AuthenticationError;
