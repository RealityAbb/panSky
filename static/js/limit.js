//-------------------limit
function inspect(obj){
   if(obj){
      var value = parseInt(obj.value);
      if(value>65535||value<0){
         alert("端口号必需在0-65535之间");
         if(obj.setSelectionRange){
          obj.setSelectionRange(0,obj.value.length);
          obj.focus();
      }else if(obj.createTextRange){
          var rng = obj.createTextRange();
          rng.select();
          obj.focus();
     }
      }
   }
}

function back1(obj){
    if(obj){
        var front= document.getElementById("sp1").value;
        var value = document.getElementById("sp2").value;
    if(front>value){
        alert("请按照由小到大的顺序输入端口号！");
        if(obj.setSelectionRange){
              obj.setSelectionRange(0,obj.value.length);
              obj.focus();
            }else if(obj.createTextRange){
              var rng = obj.createTextRange();
              rng.select();
              obj.focus();
                }
        }else{
            var value = parseInt(obj.value);
          if(value>65535||value<0){
             alert("端口号必需在0-65535之间");
             if(obj.setSelectionRange){
              obj.setSelectionRange(0,obj.value.length);
              obj.focus();
            }else if(obj.createTextRange){
              var rng = obj.createTextRange();
              rng.select();
              obj.focus();
                }
            }
        }
    }   
}

function back2(obj){
    if(obj){
        var front= document.getElementById("dp1").value;
        var value = document.getElementById("dp2").value;
    if(front>value){
        alert("请按照由小到大的顺序输入端口号！");
        if(obj.setSelectionRange){
              obj.setSelectionRange(0,obj.value.length);
              obj.focus();
            }else if(obj.createTextRange){
              var rng = obj.createTextRange();
              rng.select();
              obj.focus();
                }
        }else{
            var value = parseInt(obj.value);
          if(value>65535||value<0){
             alert("端口号必需在0-65535之间");
             if(obj.setSelectionRange){
              obj.setSelectionRange(0,obj.value.length);
              obj.focus();
            }else if(obj.createTextRange){
              var rng = obj.createTextRange();
              rng.select();
              obj.focus();
                }
            }
        }
    }   
}

function back3(obj){
    if(obj){
        var front= document.getElementById("esp1").value;
        var value = document.getElementById("esp2").value;
    if(front>value){
        alert("请按照由小到大的顺序输入端口号！");
        if(obj.setSelectionRange){
              obj.setSelectionRange(0,obj.value.length);
              obj.focus();
            }else if(obj.createTextRange){
              var rng = obj.createTextRange();
              rng.select();
              obj.focus();
                }
        }else{
            var value = parseInt(obj.value);
          if(value>65535||value<0){
             alert("端口号必需在0-65535之间");
             if(obj.setSelectionRange){
              obj.setSelectionRange(0,obj.value.length);
              obj.focus();
            }else if(obj.createTextRange){
              var rng = obj.createTextRange();
              rng.select();
              obj.focus();
                }
            }
        }
    }   
}

function back4(obj){
    if(obj){
        var front= document.getElementById("edp1").value;
        var value = document.getElementById("edp2").value;
    if(front>value){
        alert("请按照由小到大的顺序输入端口号！");
        if(obj.setSelectionRange){
              obj.setSelectionRange(0,obj.value.length);
              obj.focus();
            }else if(obj.createTextRange){
              var rng = obj.createTextRange();
              rng.select();
              obj.focus();
                }
        }else{
            var value = parseInt(obj.value);
          if(value>65535||value<0){
             alert("端口号必需在0-65535之间");
             if(obj.setSelectionRange){
              obj.setSelectionRange(0,obj.value.length);
              obj.focus();
            }else if(obj.createTextRange){
              var rng = obj.createTextRange();
              rng.select();
              obj.focus();
                }
            }
        }
    }   
}