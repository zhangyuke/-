<?php
namespace app\index\controller;

use app\index\model\UsersModel;
use think\Controller;
/**
 * Class Wachat   微信
 * @package app\index\controller
 */
class Wxpay extends Controller
{
    protected   $appid  = '********';//微信公众号id
    protected   $secret = '********'; //微信公众号AppSecret
    protected   $key    = '***********';//商户平台设置的密钥
    protected   $mch_id = '******';//商户号 
 
    public function pay()
    {
      //查询订单
      $id=input('param.order_id');
       if(!$id) {
            return json(['status' => 302, 'message' => '没有代付款订单']);
        }
        $row =db('order')->where(['id'=>$id])->find();
        if(!$row || $row['status']!=1 || $row['true_price'] <1){
            return ajax(-1,'查询订单失败');
        }
        #重置订单号
            $yCode = array('A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z');
            $code = $yCode[intval(date('Y')) - 2011] . strtoupper(dechex(date('m'))) . date('d') . time() . substr(microtime(), 2, 5) . sprintf('%02d', rand(0, 99));
            db('order')->where(['id' => $id])->update(['order_sn'=>$code,'updated_at'=>date('Y-m-d H:i:s',time())]);
            // while (db('order')->where(['order_sn' => $code])->find()) {
            //     db('order')->where(['id' => $id])->update(['order_sn'=>$code,'updated_at'=>date('Y-m-d H:i:s',time())]);
            // }
            $row=db('order')->where(['id' => $id])->find();
        $money=$row['true_price'];
        #同步跳转
        $redirect_url='';
        if($row['groups']==1){ //普通商品
            $redirect_url=WEB_FRONT.'/PaymentSuccess?money='.$money;
        }elseif($row['groups']==2){ //拼团商品
            $redirect_url=WEB_FRONT.'/groupsSuccess?id='.$row['groups_id'];
        }
        #异步通知跳转
        $notify_url=WEB_URL.'/index/Not/wx_notify';
      if (is_weixin()){ //公众号支付
            $openid=db('users')->where(['id'=>$row['uid']])->value('openid');
            if(!$openid){
                $url=WEB_URL.'/index/Wachat/wechat_phone?user_id='.$row['uid'];
                exit('<script>alert("微信支付需要授权绑定");window.location.href="'.$url.'"</script>');
                //header("Location:".$url);
                //return ajax(-1,'参数错误请重新登录');
            }
            $total_fee= (int) $money * 100;
            $body='美阿密新零售';
            $order_sn=$row['order_sn'];
            $res=$this->payweixin($openid,$total_fee,$body,$order_sn,$notify_url);
            $this->assign("res",$res);
            $this->assign("redirect_url",$redirect_url);
            return  $this->fetch("index");
      }else{  
        //非微信浏览器
            //h5支付不用传递openid 此处与微信jsapi支付不同
            $openid='';
            $total_fee= (int) $money * 100;
            $body='美阿密新零售';
            $order_sn=$row['order_sn'];
            $res=$this->payh5($openid,$total_fee,$body,$order_sn,$notify_url);
            $res['mweb_url']=$res['mweb_url'].'&redirect_url='.$redirect_url;
            $this->assign("res",$res);
            return  $this->fetch("h5");
      }
    }

    /** 
     * 微信退款 
     * @param string $order_id 订单ID 
     * @return 成功时返回(array类型)，其他抛异常 
     */

    function wxRefund($order_id) {
          date_default_timezone_set("Asia/Shanghai");
          $date = date("YmdHis");
          $order = db('order')->where(['id'=>$order_id])->find(); 
          $appid = $this->appid;
          $mch_id =$this->mch_id;
          $out_trade_no = $order['order_sn'];
          $op_user_id = "美阿密";
          $out_refund_no = $date;
          $total_fee = "1";
          $refund_fee = "1";
        //  $transaction_id = "4009542001201706206596667604";
          $key = $this->key;
          $nonce_str = $this->createNoncestr();
          $ref = strtoupper(md5("appid=$appid&mch_id=$mch_id&nonce_str=$nonce_str&op_user_id=$op_user_id"
                  . "&out_refund_no=$out_refund_no&out_trade_no=$out_trade_no&refund_fee=$refund_fee&total_fee=$total_fee"
                  . "&key=$key")); //sign加密MD5
          $refund = array(
          'appid' =>$appid, //应用ID，固定
          'mch_id' => $mch_id, //商户号，固定
          'nonce_str' => $nonce_str, //随机字符串
          'op_user_id' => $op_user_id, //操作员
          'out_refund_no' => $out_refund_no, //商户内部唯一退款单号
          'out_trade_no' => $out_trade_no, //商户订单号,pay_sn码 1.1二选一,微信生成的订单号，在支付通知中有返回
          // 'transaction_id'=>'1',//微信订单号 1.2二选一,商户侧传给微信的订单号
          'refund_fee' => $refund_fee, //退款金额
          'total_fee' => $total_fee, //总金额
          'sign' => $ref//签名
          );
          $url = "https://api.mch.weixin.qq.com/secapi/pay/refund";
          ; //微信退款地址，post请求
          $xml = $this->arrayToXml($refund);
          $ch = curl_init();
          curl_setopt($ch, CURLOPT_URL, $url);
          // curl_setopt($ch, CURLOPT_HEADER, 1);
          curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
          curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 1); //证书检查
            // 设置证书
            curl_setopt($ch, CURLOPT_SSLCERTTYPE, 'pem');
            //dump(getcwd().DIRECTORY_SEPARATOR.'/wxcert/cert/cacert.pem');die;
            curl_setopt($ch, CURLOPT_SSLCERT, getcwd().DIRECTORY_SEPARATOR.'/wxcert/cert/apiclient_cert.pem');
            curl_setopt($ch, CURLOPT_SSLCERTTYPE, 'pem');
            curl_setopt($ch, CURLOPT_SSLKEY, getcwd().DIRECTORY_SEPARATOR.'/wxcert/cert/apiclient_key.pem');
            //curl_setopt($ch, CURLOPT_SSLCERTTYPE, 'pem');
            //curl_setopt($ch, CURLOPT_CAINFO, getcwd().DIRECTORY_SEPARATOR.'/wxcert/cert/rootca.pem');
          curl_setopt($ch, CURLOPT_POST, 1);
          curl_setopt($ch, CURLOPT_POSTFIELDS, $xml);
          $xml = curl_exec($ch);
          // 返回结果0的时候能只能表明程序是正常返回不一定说明退款成功而已
              if ($xml) {
                curl_close($ch);
                // 把xml转化成数组
                libxml_disable_entity_loader(true);
                $xmlstring = $this->xmlToArray($xml);// simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOCDATA);
                $result['errNum'] = 0;
                $result['info'] = $xmlstring['err_code_des'];
            //    var_dump($result);
                return $result;
              } else {
                $error = curl_errno($ch);
                curl_close($ch);
                // 错误的时候返回错误码。
                $result['errNum'] = $error;
                return $result;
              }
        }

    public function get_acctoken($url){
        $ch = curl_init();
        curl_setopt($ch,CURLOPT_URL,$url);
        curl_setopt($ch,CURLOPT_HEADER,0);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1 );
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
        $res = curl_exec($ch);
        curl_close($ch);
        //解析json
        $user_obj = json_decode($res,true);
        return $user_obj;
    }
    


    public function wx_accounts()
    {
            $with=db('withdrawals')->where(['id'=>1])->find();
            if(!$with){
                return -1;
            }
            header('content-type:text/html;charset=utf-8');
            $data['mch_appid']=$this->appid;//商户的应用appid
            $data['mchid']=$this->mch_id;//商户ID
            $data['nonce_str']=$this->createNoncestr();//unicode();//这个据说是唯一的字符串下面有方法
            $data['partner_trade_no']=$with['pay_num'];//.time();//这个是订单号。
            $data['openid']=db('users')->where(['id'=>$with['uid']])->value('openid');//这个是授权用户的openid。。这个必须得是用户授权才能用
            $data['check_name']='NO_CHECK';//这个是设置是否检测用户真实姓名的
            $data['re_user_name']='######';//用户的真实名字
            $data['amount']=(int) 10;//提现金额
            $data['desc']='提现';//订单描述
            $data['spbill_create_ip']=$this->get_client_ipss();//这个最烦了，z'z，还得获取服务器的ip
            $secrect_key=$this->key;///这个就是个API密码。32位的。。随便MD5一下就可以了
            $data=array_filter($data);
            ksort($data);
            $str='';
            foreach($data as $k=>$v) {
                $str.=$k.'='.$v.'&';
            }
            $str.='key='.$secrect_key;
            $data['sign']=md5($str);
            $xml=$this->arrayToXml($data);
            $url='https://api.mch.weixin.qq.com/mmpaymkttransfers/promotion/transfers';
            $res=$this->accounts_curl($xml,$url);
            dump($res);die;
            $return=$this->xmltoarray($res);
            dump($return);die;
    }
           
   
  
    public  function accounts_curl($param="",$url) {
       
        $postUrl = $url;
        $curlPost = $param;
        $ch = curl_init();                                      //初始化curl
        curl_setopt($ch, CURLOPT_URL,$postUrl);                 //抓取指定网页
        curl_setopt($ch, CURLOPT_HEADER, 0);                    //设置header
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);            //要求结果为字符串且输出到屏幕上
        curl_setopt($ch, CURLOPT_POST, 1);                      //post提交方式
        curl_setopt($ch, CURLOPT_POSTFIELDS, $curlPost);           // 增加 HTTP Header（头）里的字段 
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);        // 终止从服务端进行验证
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, FALSE);
        curl_setopt($ch,CURLOPT_SSLCERT,getcwd().'/wxcert/cert/apiclient_cert.pem'); //这个是证书的位置
        curl_setopt($ch,CURLOPT_SSLKEY,getcwd().'/wxcert/cert/apiclient_key.pem'); //这个也是证书的位置
        $data = curl_exec($ch);                                 //运行curl
        curl_close($ch);
        return $data;
    }




    #获取access_token
    public function getWxAccessToken()//返回access_token
    {
        //将access_token 存在session/cookie中
//        if (session('access_token') && session('expire_time') > time()) {
//            //如果access_token在session并没有过期
//            return session('access_token');
//        } else {
            //如果access_token不存在或者已经过期，重新取access_token
            $appid=$this->appid;
            $appsecret=$this->secret;
            $url = "https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=" . $appid . "&secret=" . $appsecret;
            $res = $this->http_curl($url, 'get', 'json');
            $access_token = $res['access_token'];
            //将重新获取到的access_token存到session
//            session('access_token', $access_token);
//            session('expire_time', time() + 7200);
            return $access_token;
//        }
    }


    public function get_refresh_token($refresh_token){

        $url="https://api.weixin.qq.com/sns/oauth2/refresh_token?appid=".$this->appId."&grant_type=refresh_token&refresh_token=".$refresh_token;

        $res= file_get_contents($url);
        $res=json_decode($res,true);
        return $res;
    }

     public function get_openid_userinfo($access_token,$openid){

        $url="https://api.weixin.qq.com/sns/userinfo?access_token=".$access_token."&openid=".$openid."&lang=zh_CN";
        $res= $this->https_get($url);
        $res=json_decode($res,true);
        return $res;
     }

     protected function https_get($url, $data_type='text') {
         $cl = curl_init();
         if(stripos($url, 'https://') !== FALSE) {
             curl_setopt($cl, CURLOPT_SSL_VERIFYPEER, FALSE);
             curl_setopt($cl, CURLOPT_SSL_VERIFYHOST, FALSE);
             curl_setopt($cl, CURLOPT_SSLVERSION, 1);
         }
         curl_setopt($cl, CURLOPT_URL, $url);
         curl_setopt($cl, CURLOPT_RETURNTRANSFER, 1 );
         $content = curl_exec($cl);
         $status = curl_getinfo($cl);
         curl_close($cl);
         if (isset($status['http_code']) && $status['http_code'] == 200) {
             if ($data_type == 'json') {
                 $content = json_decode($content);
             }
             return $content;
         } else {
             return FALSE;
         }
     }


    public function payweixin($openid,$total_fee,$body,$out_trade_no,$notify_url){
        $url = "https://api.mch.weixin.qq.com/pay/unifiedorder";
        $onoce_str = $this->createNoncestr();
        $data["appid"] = $this->appid;
        $data["body"] = $body;
        $data["mch_id"] = $this->mch_id;
        $data["nonce_str"] = $onoce_str;
        $data["notify_url"] = $notify_url;
        $data["out_trade_no"] = $out_trade_no;
        $data["spbill_create_ip"] =$this->get_client_ipss();
        $data["total_fee"] = $total_fee;
        $data["trade_type"] = "JSAPI";
        $data["openid"] = $openid;
        $sign = $this->getSign($data);
        $data["sign"] = $sign;
        $xml = $this->arrayToXml($data);
        $response = $this->postXmlCurl($xml, $url);
        //将微信返回的结果xml转成数组
        $response = $this->xmlToArray($response);
        $response['package']="prepay_id=".$response['prepay_id'];
        $jsapi=array();
        $timeStamp = time();
        $jsapi['appId']=($response["appid"]);   
        $jsapi['timeStamp']=("$timeStamp");
        $jsapi['nonceStr']=($this->createNoncestr());
        $jsapi['package']=("prepay_id=" . $response['prepay_id']);
        $jsapi['signType']=("MD5");
        $jsapi['paySign']=($this->getSign($jsapi));
        $parameters = json_encode($jsapi);
        // halt($jsapi);
        //请求数据,统一下单  
        return $parameters; 
    }



    public function payh5($openid,$total_fee,$body,$out_trade_no,$notify_url){
        $url = "https://api.mch.weixin.qq.com/pay/unifiedorder";
        $onoce_str = $this->createNoncestr();
        $data["appid"] = $this->appid;
        $data["body"] = $body;
        $data["mch_id"] = $this->mch_id;
        $data["nonce_str"] = $onoce_str;
        $data["notify_url"] = $notify_url;
        $data["out_trade_no"] = $out_trade_no;
        $data["spbill_create_ip"] = $this->get_client_ipss();
        $data["total_fee"] = $total_fee;
        $data["trade_type"] = "MWEB";
        $data["scene_info"] = "{'h5_info': {'type':'Wap','wap_url':  $notify_url,'wap_name': '测试充值'}}";
        $sign = $this->getSign($data);
        $data["sign"] = $sign;        
        $xml = $this->arrayToXml($data);
        $response = $this->postXmlCurl($xml, $url);
        //将微信返回的结果xml转成数组
        $response = $this->xmlToArray($response);                
        //请求数据,统一下单                  
        return $response; 
    }

   
    #获取客户真实ip
    public function get_client_ipss(){
        if(getenv('HTTP_CLIENT_IP') && strcasecmp(getenv('HTTP_CLIENT_IP'),'unknown')) {
            $ip = getenv('HTTP_CLIENT_IP');
        } elseif(getenv('HTTP_X_FORWARDED_FOR') && strcasecmp(getenv('HTTP_X_FORWARDED_FOR'),'unknown')) {
            $ip = getenv('HTTP_X_FORWARDED_FOR');
        } elseif(getenv('REMOTE_ADDR') && strcasecmp(getenv('REMOTE_ADDR'),'unknown')) {
            $ip = getenv('REMOTE_ADDR');
        } elseif(isset($_SERVER['REMOTE_ADDR']) && $_SERVER['REMOTE_ADDR'] && strcasecmp($_SERVER['REMOTE_ADDR'], 'unknown')) {
            $ip = $_SERVER['REMOTE_ADDR'];
        }
        return preg_match ( '/[\d\.]{7,15}/', $ip, $matches ) ? $matches [0] : '';
    }
  


    // 　　/*生成签名*/
    public function getSign($Obj){
        foreach ($Obj as $k => $v){
            $Parameters[$k] = $v;
        }
        //签名步骤一：按字典序排序参数
        ksort($Parameters);
        $String = $this->formatBizQueryParaMap($Parameters, false);
        //echo '【string1】'.$String.'</br>';
        //签名步骤二：在string后加入KEY
        $String = $String."&key=".$this->key;
        //echo "【string2】".$String."</br>";
        //签名步骤三：MD5加密
        $String = md5($String);
        //echo "【string3】 ".$String."</br>";
        //签名步骤四：所有字符转为大写
        $result_ = strtoupper($String);
        //echo "【result】 ".$result_."</br>";
        return $result_;
    }
 
 
    /**
    *  作用：产生随机字符串，不长于32位
    */
    public function createNoncestr( $length = 32 ){
        $chars = "abcdefghijklmnopqrstuvwxyz0123456789"; 
        $str ="";
        for ( $i = 0; $i < $length; $i++ )  { 
            $str.= substr($chars, mt_rand(0, strlen($chars)-1), 1); 
        } 
        return $str;
    }
 
  # Array转Xml
    public function arrayToXml($arr){
        # XML头
        $xml = "<xml>";
        foreach ($arr as $key=>$val){
            if (is_numeric($val)){
                $xml.="<".$key.">".$val."</".$key.">";
            }else{
                 $xml.="<".$key."><![CDATA[".$val."]]></".$key.">";
            }
        }
        # XML尾
        $xml.="</xml>";
        //dump($xml);exit;
        return $xml;
    }
 
       
    /**
    *  作用：将xml转为array
    */
    public function xmlToArray($xml){  
        //将XML转为array       
        $array_data = json_decode(json_encode(simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOCDATA)), true);   
        return $array_data;
    }
 



        /**
    *  作用：以post方式提交xml到对应的接口url
    */
    public function postXmlCurl($xml,$url,$second=30){  
        //初始化curl       
        $ch = curl_init();
        //设置超时
        curl_setopt($ch, CURLOPT_TIMEOUT, $second);
        //这里设置代理，如果有的话
        //curl_setopt($ch,CURLOPT_PROXY, '8.8.8.8');
        //curl_setopt($ch,CURLOPT_PROXYPORT, 8080);
        curl_setopt($ch,CURLOPT_URL, $url);
        curl_setopt($ch,CURLOPT_SSL_VERIFYPEER,FALSE);
        curl_setopt($ch,CURLOPT_SSL_VERIFYHOST,FALSE);
        //设置header
        curl_setopt($ch, CURLOPT_HEADER, FALSE);
        //要求结果为字符串且输出到屏幕上
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
        //post提交方式
        curl_setopt($ch, CURLOPT_POST, TRUE);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $xml);
        //运行curl
        $data = curl_exec($ch);
        //返回结果
 
        if($data){
            curl_close($ch);
            return $data;
        }else{
            $error = curl_errno($ch);
            echo "curl出错，错误码:$error"."<br>";
            curl_close($ch);
            return false;
        }
    }
 
    /**
    *  作用：格式化参数，签名过程需要使用
    */
    public function formatBizQueryParaMap($paraMap, $urlencode)
    {
        $buff = "";
        ksort($paraMap);
        foreach ($paraMap as $k => $v){
            if($urlencode){
                $v = urlencode($v);
            }
            $buff .= $k . "=" . $v . "&";
        }
        $reqPar;
        if (strlen($buff) > 0){
            $reqPar = substr($buff, 0, strlen($buff)-1);
        }
        return $reqPar;
    }
    
    public function MakeSign($unifiedorder)
    {
        $this->values=$unifiedorder;
        //签名步骤一：按字典序排序参数
        // ksort($this->values);
        $string = $this->ToUrlParams();
//      halt($string);
        //签名步骤二：在string后加入KEY
        $string = $string . "&key=".$this->key;
        //签名步骤三：MD5加密
        $string = md5($string);
        //签名步骤四：所有字符转为大写
        $result = strtoupper($string);
        return $result;
    }

    public function ToUrlParams()
    {
        $buff = "";
        foreach ($this->values as $k => $v)
        {
            if($k != "sign" && $v != "" && !is_array($v)){
                $buff .= $k . "=" . $v . "&";
            }
        }
        $buff = trim($buff, "&");
        return $buff;
    }


    // public function array2xml($array)
    // {
    //     $xml='<xml>';
    //     foreach($array as $key=>$val){
    //         if(is_numeric($key)){
    //             $key="item id=\"$key\"";
    //         }else{
    //             //去掉空格，只取空格之前文字为key
    //             list($key,)=explode(' ',$key);
    //         } 
    //         $xml.="<$key>";
    //         $xml.=is_array($val)?$this->array2xml($val):$val;
    //         //去掉空格，只取空格之前文字为key
    //         list($key,)=explode(' ',$key);
    //         $xml.="</$key>";
            
    //     }
    //         $xml.="</xml>";

    //     return $xml;
    // }

    // public  function xml2array($xml)
    // {    
    //     //禁止引用外部xml实体
    //     libxml_disable_entity_loader(true);
    //     $values = json_decode(json_encode(simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOCDATA)), true);        
    //     return $values;
    // }

    
    public  function request_post($url = '', $param = '')
    {
        if (empty($url) || empty($param)) {
            return false;
        }
        $postUrl = $url;
        $curlPost = $param;
        $ch = curl_init(); //初始化curl
        curl_setopt($ch, CURLOPT_URL, $postUrl); //抓取指定网页
        curl_setopt($ch, CURLOPT_HEADER, 0); //设置header
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1); //要求结果为字符串且输出到屏幕上
        curl_setopt($ch, CURLOPT_POST, 1); //post提交方式
        curl_setopt($ch, CURLOPT_POSTFIELDS, $curlPost);
        $data = curl_exec($ch); //运行curl
        curl_close($ch);
        return $data;
    }

    function curl_post_ssl($url, $vars, $second=30,$aHeader=array())
    {
        $ch = curl_init();
        curl_setopt($ch,CURLOPT_TIMEOUT,$second);
        curl_setopt($ch,CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch,CURLOPT_URL,$url);
        curl_setopt($ch,CURLOPT_SSL_VERIFYPEER,false);
        curl_setopt($ch,CURLOPT_SSL_VERIFYHOST,false);
        curl_setopt($ch,CURLOPT_SSLCERTTYPE,'PEM');
        curl_setopt($ch,CURLOPT_SSLCERT,'/data/cert/php.pem');
        curl_setopt($ch,CURLOPT_SSLCERTPASSWD,'1234');
        curl_setopt($ch,CURLOPT_SSLKEYTYPE,'PEM');
        curl_setopt($ch,CURLOPT_SSLKEY,'/data/cert/php_private.pem');
        if( count($aHeader) >= 1 ){
                curl_setopt($ch, CURLOPT_HTTPHEADER, $aHeader);
        }
        curl_setopt($ch,CURLOPT_POST, 1);
        curl_setopt($ch,CURLOPT_POSTFIELDS,$vars);
        $data = curl_exec($ch);
        curl_close($ch);
        if($data){
                return $data;
        }else{
                return false;
        }
    }
   

}