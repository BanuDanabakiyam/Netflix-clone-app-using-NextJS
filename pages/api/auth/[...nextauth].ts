import NextAuth from "next-auth";
import Credentials from "next-auth/providers/credentials";
import prismadb from '../../../libs/prismadb';
import GitHubProvider from 'next-auth/providers/github';
import GoogleProvider from 'next-auth/providers/google';
import { PrismaAdapter } from "@next-auth/prisma-adapter";

import {compare} from 'bcrypt';
export default  NextAuth({
    providers:[
        GitHubProvider({
            clientId:process.env.GITHUB_ID || '',
            clientSecret:process.env.GITHUB_SECRET || '',
        }),
        GoogleProvider({
            clientId:process.env.GOOGLE_CLIENT_ID || '',
            clientSecret:process.env.GOOGLE_CLIENT_SECRET || '',
        }),
        Credentials({
            id:'credentials',
            name:'Credentials',
            credentials :{
                email :{
                    label:'email',
                    type:'text',
                },
                password :{
                    label:'password',
                    type:'password'
                }
            },
           async authorize(credentials){
                if(!credentials?.email || !credentials?.password){
                    throw new Error('Email and Password required');
                }
           const user = await prismadb.user.findUnique({
            where:{
                email : credentials.email,
            }
           }) ;
           if(!user || !user.hashedPassword){
            throw new Error("Email does not exist");
           } 
           const isCorrectPassword = await compare(credentials.password,user.hashedPassword);
           if(!isCorrectPassword){
            throw new Error("Incorrect Password");
           }
           return user;
           }
        })
    ],
    pages :{
        signIn:'/auth'
    },
    debug:process.env.NODE_ENV === 'development',
   // debug: process.env.NODE_ENV !== "production",
    adapter:PrismaAdapter(prismadb),
    session:{
        strategy:'jwt',
    },
    jwt:{
    secret:process.env.NEXTAUTH_JWT_SECRET
    },
    secret:process.env.NEXTAUTH_SECRET,

});