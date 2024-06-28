import { Router } from "express";
import {
	registerUser,
	loginUser,
	getCurrentUser,
	logoutUser,
	refreshAccessToken,
} from "../controllers/user.controller.js";
import verifyJWT from "../middlewares/auth.middleware.js";

const router = Router();

router.route("/register").post(registerUser);
router.route("/login").post(loginUser);
router.route("/refresh").post(refreshAccessToken);

// secured routes
router.route("/").get(verifyJWT, getCurrentUser);
router.route("/logout").post(verifyJWT, logoutUser);

export default router;
