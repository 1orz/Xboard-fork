<?php

namespace App\Http\Controllers\V1\User;

use App\Http\Controllers\Controller;
use App\Models\OAuthProvider;
use App\Models\User;
use App\Services\Auth\OAuthService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class OAuthController extends Controller
{
    public function __construct(private OAuthService $service)
    {
    }

    /**
     * GET /api/v1/user/oauth/list
     * 返回当前用户已绑的 identity + 所有启用的 provider，让前端画"已绑/可绑"列表。
     */
    public function list(Request $request)
    {
        /** @var User $user */
        $user = Auth::guard('sanctum')->user();

        $identities = $this->service->listIdentities($user)->map(function ($i) {
            return [
                'id' => $i->id,
                'provider_id' => $i->provider_id,
                'email_snapshot' => $i->email_snapshot,
                'name_snapshot' => $i->name_snapshot,
                'created_at' => $i->created_at?->getTimestamp(),
            ];
        });

        $providers = OAuthProvider::where('enable', true)
            ->orderBy('sort', 'ASC')
            ->orderBy('id', 'ASC')
            ->get()
            ->map(function (OAuthProvider $p) {
                return [
                    'id' => $p->id,
                    'identifier' => $p->identifier,
                    'name' => $p->name,
                    'icon' => $p->icon,
                    'allow_bind' => (bool) $p->allow_bind,
                ];
            })->values();

        return $this->success([
            'identities' => $identities,
            'providers' => $providers,
            'has_password' => !empty($user->password),
        ]);
    }

    /**
     * POST /api/v1/user/oauth/unbind
     */
    public function unbind(Request $request)
    {
        $request->validate(['identity_id' => 'required|integer']);
        /** @var User $user */
        $user = Auth::guard('sanctum')->user();

        $result = $this->service->unbind($user, (int) $request->input('identity_id'));
        return match ($result['kind']) {
            'ok' => $this->success(true),
            'not_found' => $this->fail([404, '未找到该绑定']),
            'last_login_method' => $this->fail([400, '这是您唯一的登录方式，请先设置密码再解绑']),
            default => $this->fail([500, '解绑失败']),
        };
    }

    /**
     * POST /api/v1/user/oauth/confirmBindCandidate
     * 用户在 Login 页带着 oauth_bind=<cand> 登录成功后调，把缓存里的 profile 真正绑到当前账号。
     */
    public function confirmBindCandidate(Request $request)
    {
        $request->validate(['candidate_token' => 'required|string']);
        /** @var User $user */
        $user = Auth::guard('sanctum')->user();

        $result = $this->service->confirmCandidate($user, (string) $request->input('candidate_token'));
        return match ($result['kind']) {
            'ok' => $this->success(true),
            'in_use_by_other' => $this->fail([400, '该第三方账号已被其他用户绑定']),
            'user_already_bound' => $this->fail([400, '您已绑定该 provider 的其他账号，请先解绑']),
            'invalid' => $this->fail([400, '绑定凭证无效或已过期']),
            default => $this->fail([500, '绑定失败']),
        };
    }
}
