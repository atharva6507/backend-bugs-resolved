import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js"
import { User } from "../models/user.model.js"
import { uploadOnCloudinary } from "../utils/cloudinary.js"
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";


// function to generate refresh and access tokens
const generateAccessAndRefreshTokens = async (userId) => {
    try {
        const user = await User.findById(userId)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()

        user.refreshToken = refreshToken
        await user.save({ validateBeforeSave: false })

        return { accessToken, refreshToken }


    } catch (error) {
        throw new ApiError(500, "Something went wrong while generating referesh and access token")
    }
}


// register user controller
const registerUser = asyncHandler(async (req, res) => {
    // get user details from frontend
    // validation - not empty
    // check if user already exists: username, email
    // check for images, check for avatar
    // upload them to cloudinary, avatar
    // create user object - create entry in db
    // remove password and refresh token field from response
    // check for user creation
    // return res


    const { fullName, email, username, password } = req.body
    //console.log("email: ", email);

    if (
        [fullName, email, username, password].some((field) => field?.trim() === "")
    ) {
        throw new ApiError(400, "All fields are required")
    }

    const existedUser = await User.findOne({
        $or: [{ username }, { email }]
    })

    if (existedUser) {
        throw new ApiError(409, "User with email or username already exists")
    }
    //console.log(req.files);

    const avatarLocalPath = req.files?.avatar[0]?.path;
    //const coverImageLocalPath = req.files?.coverImage[0]?.path;

    let coverImageLocalPath;
    if (req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0) {
        coverImageLocalPath = req.files.coverImage[0].path
    }


    if (!avatarLocalPath) {
        throw new ApiError(400, "Avatar file is required")
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath)
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if (!avatar) {
        throw new ApiError(400, "Avatar file is required")
    }


    const user = await User.create({
        fullName,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        email,
        password,
        username: username.toLowerCase()
    })

    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )

    if (!createdUser) {
        throw new ApiError(500, "Something went wrong while registering the user")
    }

    return res.status(201).json(
        new ApiResponse(200, createdUser, "User registered Successfully")
    )

})


// login user controller
const loginUser = asyncHandler(async (req, res) => {
    // req body -> data
    // username or email
    //find the user
    //password check
    //access and referesh token
    //send cookie

    const { email, username, password } = req.body

    if (!(username || email)) {
        throw new ApiError(400, "username or email is required")
    }

    const user = await User.findOne({
        $or: [{ username }, { email }]
    })

    if (!user) {
        throw new ApiError(404, "User does not exist")
    }

    const isPasswordValid = await user.isPasswordCorrect(password)

    if (!isPasswordValid) {
        throw new ApiError(401, "Invalid user credentials")
    }

    const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(user._id)

    const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
        .status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", refreshToken, options)
        .json(
            new ApiResponse(
                200,
                {
                    user: loggedInUser //, accessToken, refreshToken
                },
                "User logged In Successfully"
            )
        )

})


// logout user controller
const logoutUser = asyncHandler(async (req, res) => {
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {
                refreshToken: undefined
            }
        },
        {
            new: true
        }
    )

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
        .status(200)
        .clearCookie("accessToken", options)
        .clearCookie("refreshToken", options)
        .json(new ApiResponse(200, {}, "User logged Out"))
})


// refresh accessToken controller
const refreshAccessToken = asyncHandler(async (req, res) => {
    /*
        to refresh the accessToken, user must have non-expired refreshToken
        get refreshToken
        verify incoming refreshToken
    */

    //console.log('in route refresh');

    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken

    // console.log("incoming: ",incomingRefreshToken);


    if (!incomingRefreshToken) {
        throw new ApiError(401, "Unauthorised Request!!")
    }

    const isAuthorized = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET)

    if (!isAuthorized) {
        throw new ApiError(401, "Unauthorized request!!")
    }

    const user = await User.findById(isAuthorized?._id)

    if (!user) {
        throw new ApiError(400, "Invalid Refresh Token!!")
    }

    if (incomingRefreshToken !== user?.refreshToken) {
        throw new ApiError(401, "Refresh Token expired!!")
    }

    const { newRefreshToken, newAccessToken } = await generateAccessAndRefreshTokens(user._id)

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
        .status(200)
        .cookie("accessToken", newAccessToken, options)
        .cookie("refreshToken", newRefreshToken, options)
        .json(
            new ApiResponse(
                200,
                { refreshToken: newRefreshToken, accessToken: newAccessToken },
                "Access Token Refreshed"
            )
        )

})


// changePassword
const changePassword = asyncHandler(async (req, res) => {

    /*
        get oldPassword and newPassword
        find user in database as user is loggedin, we can get user's id 
        once we get user then we can cross verify oldPassword with existing password in database
        encrypt newPassword and save it in data
    */
    const { oldPassword, newPassword, confirmPassword } = req.body

    // console.log(`received oldPassword: ${oldPassword}`)

    if (oldPassword === newPassword) {
        throw new ApiError(400, "New Password cannot be your existing Password, try different New Password!!")
    }

    if (newPassword !== confirmPassword) {
        throw new ApiError(400, "Enter correct Password again to confirm!!")
    }

    const user = await User.findById(req.user?._id) // returns user object
    if (!user) {
        throw new ApiError(404, "User not Found!!")
    }

    const verifiedUser = await user.isPasswordCorrect(oldPassword) // returns bool
    if (!verifiedUser) {
        throw new ApiError(401, "Incorrect Old Password!!")
    }

    // const encryptedPassword = await bcrypt.hash(newPassword, 10)  no need to do this hashing as it is done in pre hook (save)

    user.password = newPassword
    await user.save({validateBeforeSave: true})

    res
        .status(200)
        .json(
            new ApiResponse(
                200,
                {},
                "Password changed Successfully!!"
            )
        )
})


export {
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    changePassword
}