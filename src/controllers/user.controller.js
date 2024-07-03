import mongoose, { isValidObjectId } from "mongoose";
import jwt from "jsonwebtoken";

import User from "../models/user.model.js";
import { validateUser } from "../utils/validators.js";
import asyncHandler from "../utils/asyncHandler.js";
import ApiError from "../utils/ApiError.js";
import ApiResponse from "../utils/ApiResponse.js";

const options = {
	httpOnly: true,
	secure: true,
};

// helper methods
const generateAccessAndRefreshTokens = async (userId) => {
	try {
		const user = await User.findById(userId);
		const accessToken = await user.generateAccessToken();
		const refreshToken = await user.generateRefreshToken();

		user.refreshToken = refreshToken;
		await user.save({ validateBeforeSave: false });

		return { accessToken, refreshToken };
	} catch (error) {
		throw new ApiError(500, "Error generating tokens");
	}
};

// controller functions
const registerUser = asyncHandler(async (req, res) => {
	const { name, email, password } = req.body;

	const { error } = validateUser({ name, email, password });
	if (error) {
		throw new ApiError(
			400,
			`Validation error: ${error.details[0].message}`
		);
	}

	const existingUser = await User.findOne({ email });
	if (existingUser) {
		throw new ApiError(
			409,
			"A user with the provided email already exists"
		);
	}

	const user = await User.create({ name, email, password });

	const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(
		user._id
	);

	const loggedInUser = user.toObject();
	delete loggedInUser.password;
	delete loggedInUser.refreshToken;

	return res
		.status(200)
		.cookie("accessToken", accessToken, options)
		.cookie("refreshToken", refreshToken, options)
		.json(
			new ApiResponse(
				200,
				{
					user: loggedInUser,
					accessToken,
					refreshToken,
				},
				"User registered and logged in successfully"
			)
		);
});

const loginUser = asyncHandler(async (req, res) => {
	const { email, password } = req.body;

	const { error } = validateUser({ email, password });
	if (error) {
		throw new ApiError(
			400,
			`Validation error: ${error.details[0].message}`
		);
	}

	const user = await User.findOne({ email });
	if (!user) {
		throw new ApiError(404, "User not found");
	}

	const isPasswordValid = await user.isPasswordCorrect(password);
	if (!isPasswordValid) {
		throw new ApiError(401, "Invalid Credentials");
	}

	const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(
		user._id
	);

	const loggedInUser = user.toObject();
	delete loggedInUser.password;
	delete loggedInUser.refreshToken;

	return res
		.status(200)
		.cookie("accessToken", accessToken, options)
		.cookie("refreshToken", refreshToken, options)
		.json(
			new ApiResponse(
				200,
				{
					user: loggedInUser,
					accessToken,
					refreshToken,
				},
				"User logged in successfully"
			)
		);
});

const getCurrentUser = asyncHandler(async (req, res) => {
	const currentUser = req.user.toObject();
	return res
		.status(200)
		.json(
			new ApiResponse(
				200,
				currentUser,
				"Current user retrieved successfully"
			)
		);
});

const logoutUser = asyncHandler(async (req, res) => {
	await User.findByIdAndUpdate(
		req.user?._id,
		{
			$unset: {
				refreshToken: 1,
			},
		},
		{
			new: true,
		}
	);

	return res
		.status(200)
		.clearCookie("accessToken", options)
		.clearCookie("refreshToken", options)
		.json(new ApiResponse(200, {}, "User logged out successfully"));
});

const refreshAccessToken = asyncHandler(async (req, res) => {
	const incomingRefreshToken =
		req.cookies?.refreshToken || req.body?.refreshToken;

	if (!incomingRefreshToken) {
		throw new ApiError(401, "Unauthorized request");
	}

	try {
		const decodedToken = jwt.verify(
			incomingRefreshToken,
			process.env.REFRESH_TOKEN_SECRET
		);
		const user = await User.findById(decodedToken?._id);

		if (!user || incomingRefreshToken !== user?.refreshToken) {
			throw new ApiError(401, "Invalid or expired refresh token.");
		}

		const { accessToken, refreshToken: newRefreshToken } =
			await generateAccessAndRefreshTokens(user._id);

		return res
			.status(200)
			.cookie("accessToken", accessToken, options)
			.cookie("refreshToken", newRefreshToken, options)
			.json(
				new ApiResponse(
					200,
					{ accessToken, refreshToken: newRefreshToken },
					"Access token refreshed successfully."
				)
			);
	} catch (error) {
		throw new ApiError(401, error?.message || "Invalid refresh token");
	}
});

export {
	registerUser,
	loginUser,
	getCurrentUser,
	logoutUser,
	refreshAccessToken,
};
