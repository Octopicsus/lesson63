# Express Auth API

Simple web application built with Express.js featuring user authentication.

## Usage

1. Start the application using one of the run commands above
2. Navigate to http://localhost:3000
3. Use the demo credentials (admin/admin) or register a new user
4. Explore the authentication features

## Demo User

For testing purposes, a demo user is already created:
- **Username:** `admin`
- **Password:** `admin`

## Installation

```bash
npm install
```

### Development mode (with auto-reload):
```bash
npm run dev
```

### Production mode:
```bash
npm start
```

The application will be available at: http://localhost:3000

## API Routes

### Web Routes (HTML Pages)

#### `GET /`
- **Description:** Main login page with auto-logout for authenticated users
- **Returns:** Login form (EJS template)
- **Usage:** Navigate to homepage to see login interface

#### `POST /`
- **Description:** Process login form submission
- **Body:** `{ name: string, password: string }`
- **Returns:** Redirects to protected page or login page with error
- **Usage:** Submit login credentials through web form

#### `GET /protected`
- **Description:** Protected user dashboard page
- **Returns:** User information page (EJS template)
- **Usage:** Accessible only for authenticated users, shows user details

#### `GET /auth/register`
- **Description:** Registration page
- **Returns:** Registration form (EJS template)
- **Usage:** Navigate to registration interface

#### `POST /auth/register`
- **Description:** Process registration form submission
- **Body:** `{ name: string, password: string }`
- **Returns:** Redirects to homepage after successful registration
- **Usage:** Submit new user registration through web form

#### `POST /auth/logout`
- **Description:** User logout
- **Returns:** Redirects to homepage
- **Usage:** Logout current user session

### API Routes (JSON Responses)

#### `POST /api/login`
- **Description:** User authentication API endpoint
- **Body:** `{ name: string, password: string }`
- **Returns:** `{ token: string, user: { id: string, name: string } }`
- **Status Codes:** 
  - `200` - Success
  - `401` - Invalid credentials
- **Usage:** Login via API call

#### `POST /api/register`
- **Description:** User registration API endpoint
- **Body:** `{ name: string, password: string }`
- **Returns:** `{ token: string, user: { id: string, name: string } }`
- **Status Codes:**
  - `200` - Success
  - `400` - User already exists
- **Usage:** Register new user via API call

#### `GET /api/protected`
- **Description:** Protected route requiring authentication
- **Headers:** `Authorization: Bearer <token>`
- **Returns:** `{ message: string, user: object }`
- **Status Codes:**
  - `200` - Success
  - `401` - No token provided
  - `403` - Invalid token
- **Usage:** Access protected data with valid JWT token

#### `POST /api/verify-token`
- **Description:** Verify JWT token validity
- **Body:** `{ token: string }`
- **Returns:** `{ valid: true, user: { id: string, name: string } }`
- **Status Codes:**
  - `200` - Valid token
  - `400` - Token required
  - `403` - Invalid token
- **Usage:** Validate existing JWT token

#### `GET /api/users`
- **Description:** Get list of all users (protected route)
- **Headers:** `Authorization: Bearer <token>`
- **Returns:** Array of users with basic info (id, name, createdAt)
- **Status Codes:**
  - `200` - Success
  - `401` - No token provided
  - `403` - Invalid token
- **Usage:** Retrieve user list for admin purposes

#### `POST /api/logout`
- **Description:** API logout endpoint
- **Headers:** `Authorization: Bearer <token>`
- **Returns:** `{ message: "Logged out successfully" }`
- **Status Codes:**
  - `200` - Success
  - `401` - Authentication required
- **Usage:** Logout via API call






