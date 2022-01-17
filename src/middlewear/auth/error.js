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
  constructor() {
    const STATUS_CODE = 401;
    super(`${STATUS_CODE}: Unauthorised`, STATUS_CODE);
    this.status = STATUS_CODE;
  }
}

export default { AuthenticationError };

