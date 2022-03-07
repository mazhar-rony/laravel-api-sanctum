<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $fields = $request->validate([
            'name' => 'required|string',
            'email' => 'required|string|unique:users,email',
            'password' => 'required|string|confirmed'
        ]);

        $user = User::create([
            'name' => $fields['name'],
            'email' => $fields['email'],
            'password' => Hash::make($fields['password'])            
        ]);

        $token = $user->createToken('mytoken')->plainTextToken;

        $response = [
            'user' => $user,
            'token' => $token
        ];

        return response($response, Response::HTTP_CREATED);
    }

    public function login(Request $request)
    {
        $fields = $request->validate([
            'email' => 'required|string',
            'password' => 'required|string'
        ]);

        // check email
        $user = User::where('email', $fields['email'])->first();

        // check password
        if(!$user || !Hash::check($fields['password'], $user->password))
        {
            return response([
                'message' => 'The provided credentials are incorrect.'
            ], Response::HTTP_UNAUTHORIZED);
        }

        $token = $user->createToken('mytoken')->plainTextToken;

        $response = [
            'user' => $user,
            'token' => $token
        ];

        return response($response, Response::HTTP_CREATED);
    }

    public function logout(Request $request)
    {
        Auth::user()->tokens()->delete();

        return response([
            'message' => 'Logged Out'
        ]);
    }
}
