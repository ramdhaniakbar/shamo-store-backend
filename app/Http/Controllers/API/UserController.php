<?php

namespace App\Http\Controllers\API;

use App\Helpers\ResponseFormatter;
use App\Http\Controllers\Controller;
use App\Models\User;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
// use Illuminate\Support\Facades\Hash;
use Laravel\Fortify\Rules\Password;

class UserController extends Controller
{
    public function register(Request $request)
    {
        // try {
            $fields = $request->validate([
                'name' => 'required|string|max:255',
                'username' => 'required|string|max:255|unique:users,username',
                'email' => 'required|string|email|max:255|unique:users,email',
                'phone' => 'nullable|string|max:255',
                'password' => 'required|string|confirmed|max:255|',
            ]);
            
            User::create([
                'name' => $fields['name'],
                'username' => $fields['username'],
                'email' => $fields['email'],
                'phone' => $fields['phone'],
                'password' => bcrypt($fields['password']),
            ]);

            $user = User::where('email', $request->email)->first();

            $token = $user->createToken('authToken')->plainTextToken;

            return ResponseFormatter::success([
                'access_token' => $token,
                'token_type' => 'Bearer',
                'user' => $user
            ], 'User Registered');

        // } catch (Exception $error) {
        //     return ResponseFormatter::error([
        //         'message' => 'Something went wrong',
        //         'error' => $error
        //     ], 'Authentication Failed', 500);
        // }
    }

    public function login(Request $request)
    {
        try {
            $fields = $request->validate([
                'email' => 'required|email',
                'password' => 'required'
            ]);

            $credentials = request(['email', 'password']);

            if (!Auth::attempt($credentials)) {
                return ResponseFormatter::error([
                    'message' => 'Unauthorized',
                ], 'Authentication Failed', 500);
            }

            $user = User::where('email', $fields['email'])->first();

            if (!$user || !Hash::check($fields['password'], $user->password, [])) {
                throw new \Exception('Invalid Credentials');
            }

            $token = $user->createToken('authToken')->plainTextToken;

            return ResponseFormatter::success([
                'access_token' => $token,
                'token_type' => 'Bearer',
                'user' => $user
            ], 'Authenticated');

        } catch (Exception $error) {
            return ResponseFormatter::error([
                'message' => 'Something went wrong',
                'error' => $error
            ], 'Authentication Failed', 500);
        }
    }

    public function fetch(Request $request)
    {
        return ResponseFormatter::success($request->user(), 'Data profile user berhasil diambil');
    }

    public function updateProfile(Request $request)
    {
        $data = $request->all();

        $user = Auth::user();
        $user->update($data);

        return ResponseFormatter::success($user, 'Profile updated');
    }

    public function logout(Request $request)
    {   
        $token = $request->user()->currentAccessToken()->delete();

        // Auth::user()->tokens->each(function($token) {
        //     $token->delete();
        // });
        
        return ResponseFormatter::success($token, 'Token Revoke');
    }
}
