// // // const notifier = require('node-notifier');
// // // const path = require('path');
// // // notifier.notify({
// // //     title: 'Notification Title',
// // //     message: 'Notification Message',
// // //     icon:'/Users/rachitdas/Desktop/final-app/images/ii.png',
// // // });

// const path=require('path')
// const {spawn}=require('child_process')
// const sudoPrompt = require('sudo-prompt');
// const osascript=require('node-osascript');

// // const block_ip=async (ip)=>{
// //     let applescript_path_block=path.join(__dirname,'block_ip.scpt')
// //       let b_ip=sudoPrompt.exec(`osascript ${applescript_path_block} ${ip}`,{name:'finalapp'},(error,stdout,stderr)=>{
// //         if(error){
// //           console.log(error)
// //         }
// //         else{
// //           console.log(stdout)
// //         }
// //       })
// //     //   let b_ip=spawn('osascript',[applescript_path_block,ip])

// // }

// // const unblock_ip=(ip)=>{

// //       let applescript_path_unblock=path.join(__dirname,'unblock_ip.scpt')
// //       // let unb_ip=sudoPrompt.exec(`osascript ${applescript_path_unblock} ${ip}`,{name:'finalapp'},(error,stdout,stderr)=>{
// //       //   if(error){
// //       //     console.log(error)
// //       //   }
// //       //   else{
// //       //     console.log(stdout)
// //       //   }
// //       // })
// //       let unb_ip=spawn('osascript',[applescript_path_unblock,ip])
// //   }
// // block_ip('192.168.100.67')

// // function executeAppleScriptWithSudo(ipToBlock) {
// //     if (!ipToBlock) {
// //       // Handle the case when no IP address is provided
// //       console.error('Please provide the IP address to block as a command-line argument.');
// //       return;
// //     }
  
// //     const blockedRule = `block return in proto tcp from ${ipToBlock} to any`;
// //     const script = `
// //         do shell script "sudo echo ${blockedRule} | sudo tee -a /etc/pf.conf"
// //         do shell script "sudo pfctl -f /etc/pf.conf"
// //         do shell script "sudo pfctl -E"
// //     `;
  
// //     // Use sudo-prompt to run the AppleScript with sudo privileges
// //     sudoPrompt.exec(script, { name: 'YourAppName'}, (error, stdout, stderr) => {
// //       if (error) {
// //         console.error('Error executing AppleScript with sudo:', error);
// //       } else {
// //         console.log('AppleScript executed with sudo successfully');
// //       }
// //     });
// //   }


// // executeAppleScriptWithSudo('192.168.100.67')


// // const appleScriptPath = path.join(__dirname, 'block_ip.scpt');
// //   osascript.executeFile(appleScriptPath,{varName:'192,168.100.111'},(err, result) => {
// //     if (err) {
// //       console.error('Error executing AppleScript:', err);
// //     } else {
// //       console.log('AppleScript executed successfully:', result);
// //     }
// //   });

// // const sudo=require('sudo-prompt');

// // const scriptPath = '/Users/rachitdas/Desktop/final-app/src/block_ip.scpt';
// // const ip = '192.168.100.111';
// // const ipp='/usr/bin/osascript'

// // const options = {
// //   name: 'finalapp',
// // };

// // sudo.exec(`${ipp} ${scriptPath}`, options, (error, stdout, stderr) => {
// //   if (error) {
// //     console.error(error);
// //   } else {
// //     console.log('Script executed successfully!');
// //     console.log(stdout);
// //   }
// // });

// const scriptPath = '/Users/rachitdas/Desktop/final-app/src/block_ip.scpt';
// const ip = '192.168.100.111';

// const osascriptCmd = spawn('osascript', [scriptPath, ip]);

// osascriptCmd.stdout.on('data', (data) => {
//   console.log(`stdout: ${data}`);
// });

// osascriptCmd.stderr.on('data', (data) => {
//   console.error(`stderr: ${data}`);
// });

// osascriptCmd.on('close', (code) => {
//   console.log(`Child process exited with code ${code}`);
// });

const client2 = () =>{
  const io=require('socket.io-client')
  const socket=io('http://127.0.0.1:8000')

  socket.on('connect',()=>{
    // information.innerHTML="Collecting logs..."
    console.log('connected to server')
  })

  socket.on('data_event2',(data)=>{
    let data2=JSON.parse(data)
    prediction=data2.prediction
    console.log(data2)
  //   if(ports.hasOwnProperty(data2.dst_port)){
  //     ports[data2.dst_port]+=1
  //   }
  //   else{
  //     ports[data2.dst_port]=1
  //   }
  //   if(prediction.toString().includes('No attack detected')){
  //     benign+=1
  //     allbenign+=1
  //     // benignDetails.innerHTML=benign.toString()
  //     // alltimeBenign.innerHTML=allbenign.toString()
  //   }
  //   else if(!prediction.toString().includes('Collecting logs...')){
  //     malicious+=1
  //     allmalicious+=1
  //     // maliciousDetails.innerHTML=malicious.toString()
  //     // alltimeMalicious.innerHTML=allmalicious.toString()
  //     notifier.notify({
  //       title:'Attack Detected on '+datetime,
  //       message:prediction.toString(),
  //     })
  //     addCard(cards,datetime,prediction.toString())
  //     histt[datetime]=data.toString()
  //     if(!ip_address.includes(data2.src_ip) && !portBlock.includes(data2.dst_port)){
  //       ip_address.push(data2.src_ip)
  //       block_ip(data2.src_ip,data2.dst_port)
  //     }
  //   }
  //   // information.innerHTML=prediction.toString()
  //   // src_ip.innerHTML=`source ip : ${data2.src_ip}`
  //   // dst_ip.innerHTML=`destination ip : ${data2.dst_ip}`
  //   // dst_port.innerHTML=`destination port : ${data2.dst_port}`
  //   // moreDate.innerHTML=datetime.toString()
  //   // moreAttack.innerHTML=prediction.toString()
  //   // lastconnection['lastconnection']=[datetime.toString(),prediction.toString()]
  //   // fs.writeFile(path.join(__dirname,'lastconnection.json'),JSON.stringify(lastconnection),(err)=>{
  //   //       if(err){
  //   //         console.log(err)
  //   //         throw err
  //   //       }
  //   //     })
    })
  socket.on('disconnect',()=>{
    console.log('disconnected from server')
  })
}

client2()