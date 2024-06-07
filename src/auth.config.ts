import bcrypt from "bcryptjs";
import type { NextAuthConfig } from "next-auth";
import Credentials from "next-auth/providers/credentials";
import Github from "next-auth/providers/github";
import Google from "next-auth/providers/google";

import { LoginSchema } from "./schemas";
import { getUserByEmail } from "./services/user";

export default {
  providers: [
    Github({
      clientId: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
    }),
    Google({
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    }),
    Credentials({
      async authorize(credentials) {
        const validatedFields = LoginSchema.safeParse(credentials);

        if (validatedFields.success) {
          const { email, password } = validatedFields.data;

          const user = await getUserByEmail(email);
          if (!user || !user.password) return null;

          const passwordsMatch = await bcrypt.compare(password, user.password);

          if (passwordsMatch) return user;
        }

        return null;
      },
    }),
    {
      id: "tumblr",
      name: "Tumblr",
      type: "oauth",
      version: "1.0", // This should be correct
      params: {
        scope: "", // Adjust scope if needed
      },
      accessTokenUrl: "https://www.tumblr.com/oauth/access_token",
      requestTokenUrl: "https://www.tumblr.com/oauth/request_token",
      authorizationUrl: "https://www.tumblr.com/oauth/authorize?oauth_token=",
      profileUrl: "https://api.tumblr.com/v2/user/info",
      profile: (profile) => {
        return {
          id: profile.response.user.name,
          name: profile.response.user.name,
          email: null, // Tumblr doesn't provide email
        };
      },
      clientId: process.env.TUMBLR_CLIENT_ID,
      clientSecret: process.env.TUMBLR_CLIENT_SECRET,
    },
  ],
} satisfies NextAuthConfig;

