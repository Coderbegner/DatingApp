import { Component, OnInit } from '@angular/core';
import { AuthService } from 'src/_services/auth.service';

@Component({
  selector: 'app-nav',
  templateUrl: './nav.component.html',
  styleUrls: ['./nav.component.css']
})
export class NavComponent implements OnInit {
 model: any= {};
  constructor(private authmodule:AuthService) { }

  ngOnInit() {
  }
Login() {
  this.authmodule.login(this.model).subscribe(next=>{
    console.log('logged in sucessfully');
  },error=>{
    console.log('Failed to login');
  }
  );
}
loggedIn(){
  const token=localStorage.getItem('token');
  return !!token;
}
loggedOut()
{
  localStorage.removeItem('token');
  console.log('Logged Out')
}
}
