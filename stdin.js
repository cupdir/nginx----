/**
  +------------------------------------------------------------------------------
  实时监控并发用户
  +------------------------------------------------------------------------------
  @author   cupdir <cupdir@gmail.com>
  @version  $Id$
  +------------------------------------------------------------------------------
 */

/* 
1,同级目录新建一个logs/ip.log文件

2,tailf  /data/logs/nginx/www.test.com.log |node /home/wwwroot/xiaomi/node-center/stdin.js 200

日志文件，主要是过滤IP。 管道命令， 200是要进入黑洞的并发数

注：利用tailf 来读NGINX访问日志按行读记录，存放内存进行分析，对生产环境业务没有影响，考虑tailf性能即可.
 */

var HOME = __dirname,/**设置根目录**/  crypto = require('crypto'),/**用于MD5加密**/ fs = require('fs'), /**文件操作**/log = require('log4js'),logger = log.getLogger('system'),exec = require('child_process').exec;
log.configure({
    appenders: [
    {
        type: 'console'
    },
    {   
        type: 'file', 
        filename: HOME+'/logs/'+new Date().getFullYear()+new Date().getMonth()+new Date().getDate()+'_'+process.pid+'.log', 
        category: 'system'
    }
    ]
});  
process.stdin.resume();
process.stdin.setEncoding('utf8');
var ENV_BING = parseInt(process.argv[2]); //得到一个并发的阀值选项
var o =  hash_ip =  new Array(); //存放过滤的IP数据 保存方式 时间秒:{IP列表,次数}
process.stdin.on('data',function($ip_hash){ //得到从管道进入的流
    var today = new Date(),m = today.getMonth()+1,d = today.getDate(),y=today.getFullYear(),h=today.getHours(),i = today.getMinutes(),s = today.getSeconds();
    var time = new Date(m+'/'+d+'/'+y+' '+h+':'+i+':'+s).getTime()/1000;  //得到以秒为单位的UNIX时间戳
    m_ip  = $ip_hash.match(/([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+){0,1}/); //过滤出一个IP,匹配一次，确保每行第一个IP就是用户访问IP
    if(typeof(m_ip) == 'object'){
        m_time_hash = crypto.createHash('md5').update(time.toString(),'utf8').digest("hex"); //日志存在IP，HASH
        if(typeof o[m_time_hash] == 'undefined'){
            o[m_time_hash] = [{
                'ip':m_ip[0],
                'time':m_time_hash,
                'count':0,
                'request':time
            }]; //初始化一个IP列表，在当前时间以秒单位为空的时候进入
        }
        o[m_time_hash].fock(m_time_hash,m_ip[0],time,function(doc){
            //留个接口。方便内部操作
                if(hash_ip.ip_in_array(doc.ip) == false){
                    logger.trace(doc.ip);
                    route = exec('route add -host '+m_ip[0]+' gw 10.100.2.200',function(error, stdout, stderr){
                        if (error !== null) {
                            console.log('路由已经存在');
                        }                      
                    });
                    hash_ip.push(doc.ip);   //修改为内存操作
                }
        });                  
    }
});

//增加一个 Array方法
Array.prototype.fock = function(m_time_hash,ip,time,callback){
    var in_hash_ip = false,in_bing_hash = [];
    o[m_time_hash].forEach(function(doc){
        if(doc.time == m_time_hash &&  doc.ip == ip){ //IP和时间都对应，进入阀值判断
            //logger.info(ip);
            if(doc.count >= ENV_BING){ //大于等于这个数，删除这个元素，并返回给lock调用者。在调用者里加入黑洞代码                 
                o[m_time_hash].pop(); //存在并发，刷新hash表。  
                callback(doc);
            }else{
                doc.count++; //不是并发，一直累计并发数，
                o[m_time_hash] = [doc];               
            }
        }else{ //时间和IP都不对应，从新创建一个
            doc.count = 0;
            doc.m_time_hash = m_time_hash;
            o[m_time_hash].push(doc)
        }
    })    
}
//查找当前请求IP是否存在并发IP列表中
Array.prototype.ip_in_array = function in_array(needle, strict) {
    for(var i = 0; i < this.length; i++) {
        if(strict) {
            if(this[i] === needle) {
                return true;
            }
        } else {
            if(this[i] == needle) {
                return true;
            }
        }
    }

    return false;
}
console.log('服务启动成功');