<?php

namespace App;

use Illuminate\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Access\Authorizable as AuthorizableContract;
use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Laravel\Lumen\Auth\Authorizable;
use Spatie\Permission\Traits\HasRoles;

class User extends Model implements AuthenticatableContract, AuthorizableContract
{
    use Authenticatable, Authorizable, HasRoles;

    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $fillable = [
        'name',
        'email',
    ];

    /**
     * The attributes excluded from the model's JSON form.
     *
     * @var array
     */
    protected $hidden = [
        'password',
        'email_verified_at',
        'token_register',
        'roles'
    ];
    
    /**
     * The attributes appended to the model's JSON form.
     *
     * @var array
     */
    protected $appends = ['roleNames'];

    /**
     * Get the roles of the user
     *
     * @return Array
     */
    public function getRoleNamesAttribute()
    {
        return $this->roles->pluck('name');
    }

    /**
     * Create a user
     *
     * @param $name
     * @param $email
     * @param $password
     * @return User|bool
     */
    public static function createFromValues($name, $email, $password)
    {
        $user = new static;

        $user->name = $name;
        $user->email = $email;
        $user->password = Hash::make($password);
        $user->token_register = Str::random(64);

        return $user->save() ? $user : false;
    }

    /**
     * Get user by email
     *
     * @param $email
     * @return User
     */
    public static function byEmail($email)
    {
        return (new static)->where(compact('email'))->first();
    }

    /**
     * Verify by token
     *
     * @param $token
     * @return false|User
     */
    public static function verifyByToken($token)
    {
        $user = (new static)->where(['token_register' => $token, 'email_verified_at' !== NULL])->first();

        if (!$user) {
            return false;
        }

        $user->verify();

        return $user;
    }

    /**
     * Verifiy a userq
     *
     * @return bool
     */
    public function verify()
    {
        $this->token_register = null;
        $this->verified = '';

        return $this->save();
    }

    /**
     * Create password recovery token
     */
    public function createPasswordRecoveryToken()
    {
        $token = Str::random(64);

        $created = DB::table('users')->updateOrInsert(
            ['email' => $this->email],
            ['email' => $this->email, 'token_register' => $token]
        );

        return $created ? $token : false;
    }

    /**
     * Restore password by token
     *
     * @param $token
     * @param $password
     * @return false|User
     */
    public static function newPasswordByResetToken($token_register, $password)
    {
        $query = DB::table('users')->where(compact('token_register'));
        $record = $query->first();

        if (!$record) {
            return false;
        }

        $user = self::byEmail($record->email);

        $query->delete();

        return $user->setPassword($password);
    }

    /**
     * Persist a new password for the user
     *
     * @param $password
     * @return bool
     */
    public function setPassword($password)
    {
        $this->password = Hash::make($password);
        return $this->save();
    }
}
