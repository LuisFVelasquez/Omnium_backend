import { UserModel } from '../../models/user/user.js';
import bcrypt from 'bcrypt';
import { generateToken } from '../../utils/tokenUtils.js';

const resolversAuth = {
  Mutation: {
    registro: async (parent, args) => {
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(args.password, salt);
           
      const usuarioCreado = await UserModel.create({
        nombre: args.nombre,
        apellido: args.apellido,
        identificacion: args.identificacion,
        correo: args.correo,
        rol: args.rol,
        estado: args.estado,
        password: hashedPassword,
      });
      console.log('Usuario creado', usuarioCreado);
      return {
        token: generateToken({
          _id: usuarioCreado._id,
          nombre: usuarioCreado.nombre,
          apellido: usuarioCreado.apellido,
          identificacion: usuarioCreado.identificacion,
          correo: usuarioCreado.correo,
          rol: usuarioCreado.rol,
          estado: usuarioCreado.estado,
          password: usuarioCreado.password,
        }),
      };
    },

    login: async (parent, args) => {
      const usuarioEcontrado = await UserModel.findOne({ correo: args.correo });
      if (await bcrypt.compare(args.password, usuarioEcontrado.password)) {
        return {
          token: generateToken({
            _id: usuarioEcontrado._id,
            nombre: usuarioEcontrado.nombre,
            apellido: usuarioEcontrado.apellido,
            identificacion: usuarioEcontrado.identificacion,
            correo: usuarioEcontrado.correo,
            rol: usuarioEcontrado.rol,
            estado: usuarioEcontrado.estado,
            password: usuarioEcontrado.password,
          }),
        };
      }
    },
    refreshToken: async (parent, args, context) => {
      console.log('contexto', context);
      if (!context.userData) {
        return {
          error: 'token no valido',
        };
      } else {
        return {
          token: generateToken({
            _id: context.userData._id,
            nombre: context.userData.nombre,
            apellido: context.userData.apellido,
            identificacion: context.userData.identificacion,
            correo: context.userData.correo,
            rol: context.userData.rol,
            estado: context.userData.estado,
            password: context.userData.password,
          }),
        };
      }
      
    },
  },
};
export { resolversAuth };

/* validateToken: async (parent, args, context) => {
  console.log('contexto', context);
  // valdiar que el contexto tenga info del usuario. si si, refrescar el token
  // si no devolver null para que en el front redirija al login.
},
},
}; */