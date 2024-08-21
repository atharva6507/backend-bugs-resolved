import mongoose from "mongoose";

const subscriberSchema = new mongoose.Schema(
    {
        subscriber: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User"
        },
        channel: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User"
        }
    },
    {timestamps: true}
)

export const Subscriber = mongoose.model("Subscriber", subscriberSchema);