<?php

namespace App\Http\Controllers\V2\Admin;

use App\Http\Controllers\Controller;
use App\Models\OAuthProvider;
use App\Services\Auth\OAuthService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Throwable;

class OAuthProviderController extends Controller
{
    public function __construct(private OAuthService $service)
    {
    }

    public function fetch()
    {
        $providers = OAuthProvider::orderBy('sort', 'ASC')
            ->orderBy('id', 'ASC')
            ->get()
            ->map(function (OAuthProvider $p) {
                return array_merge($p->toArray(), [
                    'callback_url' => $this->service->buildCallbackUrl($p->identifier),
                ]);
            });
        return $this->success($providers);
    }

    public function save(Request $request)
    {
        $id = $request->input('id');
        $params = $request->validate([
            'identifier' => "required|string|max:32|regex:/^[a-z0-9_\-]+$/|unique:v2_oauth_provider,identifier" . ($id ? ",{$id},id" : ''),
            'name' => 'required|string|max:64',
            'icon' => 'nullable|string|max:255',
            'client_id' => 'required|string|max:255',
            'client_secret' => 'required|string|max:1024',
            'discovery_mode' => 'required|in:auto,manual',
            'issuer' => 'nullable|string|max:255',
            'authorization_endpoint' => 'nullable|string|max:512',
            'token_endpoint' => 'nullable|string|max:512',
            'userinfo_endpoint' => 'nullable|string|max:512',
            'jwks_uri' => 'nullable|string|max:512',
            'scopes' => 'nullable|string|max:512',
            'sub_attribute' => 'nullable|string|max:64',
            'email_attribute' => 'nullable|string|max:64',
            'name_attribute' => 'nullable|string|max:64',
            'email_verified_attribute' => 'nullable|string|max:64',
            'allow_register' => 'boolean',
            'allow_bind' => 'boolean',
            'enable' => 'boolean',
        ], [
            'identifier.regex' => 'identifier 只能用小写字母 / 数字 / _ / -',
        ]);

        if ($params['discovery_mode'] === 'auto' && empty($params['issuer'])) {
            return $this->fail([400, 'auto 模式必须填 issuer']);
        }
        if ($params['discovery_mode'] === 'manual') {
            foreach (['authorization_endpoint', 'token_endpoint'] as $required) {
                if (empty($params[$required])) {
                    return $this->fail([400, "manual 模式必须填 {$required}"]);
                }
            }
        }

        if (isset($params['issuer'])) {
            $params['issuer'] = $params['issuer'] ? rtrim($params['issuer'], '/') : null;
        }

        if ($id) {
            $provider = OAuthProvider::find($id);
            if (!$provider) {
                return $this->fail([404, 'provider 不存在']);
            }
            $provider->update($params);
            // identifier 改了或端点改了，旧 discovery 缓存可能失效
            $provider->refresh();
            return $this->success(true);
        }

        $params['sort'] = (OAuthProvider::max('sort') ?? 0) + 1;
        OAuthProvider::create($params);
        return $this->success(true);
    }

    public function drop(Request $request)
    {
        $provider = OAuthProvider::find($request->input('id'));
        if (!$provider) {
            return $this->fail([404, 'provider 不存在']);
        }
        $provider->delete();
        return $this->success(true);
    }

    public function show(Request $request)
    {
        $provider = OAuthProvider::find($request->input('id'));
        if (!$provider) {
            return $this->fail([404, 'provider 不存在']);
        }
        $provider->enable = !$provider->enable;
        $provider->save();
        return $this->success(true);
    }

    public function sort(Request $request)
    {
        $request->validate(['ids' => 'required|array']);
        try {
            DB::beginTransaction();
            foreach ($request->input('ids') as $k => $v) {
                OAuthProvider::where('id', $v)->update(['sort' => $k + 1]);
            }
            DB::commit();
        } catch (Throwable $e) {
            DB::rollBack();
            return $this->fail([500, '排序失败']);
        }
        return $this->success(true);
    }

    public function discover(Request $request)
    {
        $request->validate(['issuer' => 'required|string|max:255']);
        try {
            $endpoints = $this->service->fetchDiscovery((string) $request->input('issuer'));
        } catch (Throwable $e) {
            return $this->fail([400, $e->getMessage()]);
        }
        return $this->success($endpoints);
    }
}
